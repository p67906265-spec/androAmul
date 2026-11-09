package it.paolo.amulesearch;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.InputType;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.ArrayAdapter;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.Toast;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.Spinner;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

public class MainActivity extends Activity {

    private static final String PREFS = "amule_search";

    private EditText edQuery, edExt, edAvail, edMin, edMax;
    private Spinner spType, spFileType, spMinUnit, spMaxUnit;
    private Button btnSearch;
    private TextView tvCount, tvStatus;
    private ListView listView;

    private final List<EcClient.Result> results = new ArrayList<>();
    private ResultAdapter adapter;

    private volatile boolean running = false;
    private volatile boolean stopRequested = false;

    private static final String[] TYPE_LABELS = {"Globale", "Locale", "Kad"};
    private static final int[] TYPE_VALUES = {EcClient.SEARCH_GLOBAL, EcClient.SEARCH_LOCAL, EcClient.SEARCH_KAD};

    private static final String[] FILE_LABELS = {"Qualsiasi", "Audio", "Video", "Immagini", "Documenti", "Programmi", "Archivi", "Immagini CD"};
    private static final String[] FILE_VALUES = {"", "Audio", "Video", "Image", "Doc", "Pro", "Arc", "Iso"};

    private static final String[] UNITS = {"KiB", "MiB", "GiB"};
    private static final long[] UNIT_MULT = {1024L, 1024L * 1024L, 1024L * 1024L * 1024L};

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        setTitle("Ricerche");

        listView = findViewById(R.id.list);
        tvStatus = findViewById(R.id.tvStatus);

        View form = LayoutInflater.from(this).inflate(R.layout.form, listView, false);
        listView.addHeaderView(form, null, false);

        edQuery = form.findViewById(R.id.edQuery);
        edExt = form.findViewById(R.id.edExt);
        edAvail = form.findViewById(R.id.edAvail);
        edMin = form.findViewById(R.id.edMin);
        edMax = form.findViewById(R.id.edMax);
        spType = form.findViewById(R.id.spType);
        spFileType = form.findViewById(R.id.spFileType);
        spMinUnit = form.findViewById(R.id.spMinUnit);
        spMaxUnit = form.findViewById(R.id.spMaxUnit);
        btnSearch = form.findViewById(R.id.btnSearch);
        tvCount = form.findViewById(R.id.tvCount);

        spType.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, TYPE_LABELS));
        spFileType.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, FILE_LABELS));
        spMinUnit.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, UNITS));
        spMaxUnit.setAdapter(new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, UNITS));
        spMinUnit.setSelection(1);
        spMaxUnit.setSelection(1);

        adapter = new ResultAdapter();
        listView.setAdapter(adapter);

        btnSearch.setOnClickListener(v -> {
            if (running) {
                stopRequested = true;
                btnSearch.setEnabled(false);
            } else {
                startSearch();
            }
        });

        edQuery.setOnEditorActionListener((v, actionId, event) -> {
            if (actionId == EditorInfo.IME_ACTION_SEARCH
                    || (event != null && event.getKeyCode() == KeyEvent.KEYCODE_ENTER)) {
                if (!running) startSearch();
                return true;
            }
            return false;
        });

        if (prefs().getString("host", "").isEmpty()) {
            showSettings();
        } else {
            updateStatusIdle();
        }
    }

    // ---------------------------------------------------------------- impostazioni

    /** Toglie http://, percorso e porta: tiene solo l'indirizzo. */
    static String cleanHost(String in) {
        String h = in == null ? "" : in.trim();
        int i = h.indexOf("://");
        if (i >= 0) h = h.substring(i + 3);
        int slash = h.indexOf('/');
        if (slash >= 0) h = h.substring(0, slash);
        int colon = h.lastIndexOf(':');
        if (colon >= 0) h = h.substring(0, colon);
        return h.trim();
    }

    /** Porta eventualmente scritta nell'indirizzo (es. 192.168.0.111:4712), altrimenti -1. */
    static int hostPort(String in) {
        String h = in == null ? "" : in.trim();
        int i = h.indexOf("://");
        if (i >= 0) h = h.substring(i + 3);
        int slash = h.indexOf('/');
        if (slash >= 0) h = h.substring(0, slash);
        int colon = h.lastIndexOf(':');
        if (colon < 0) return -1;
        try {
            return Integer.parseInt(h.substring(colon + 1).trim());
        } catch (Exception e) {
            return -1;
        }
    }

    private SharedPreferences prefs() {
        return getSharedPreferences(PREFS, MODE_PRIVATE);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        menu.add(0, 1, 0, "Impostazioni").setShowAsAction(MenuItem.SHOW_AS_ACTION_NEVER);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == 1) {
            showSettings();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void showSettings() {
        SharedPreferences p = prefs();
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (20 * getResources().getDisplayMetrics().density);
        box.setPadding(pad, pad / 2, pad, 0);

        final EditText host = new EditText(this);
        host.setHint("Indirizzo IP LAN (es. 192.168.0.111)");
        host.setSingleLine(true);
        host.setText(p.getString("host", ""));

        final EditText port = new EditText(this);
        port.setHint("Porta EC (default 4712)");
        port.setInputType(InputType.TYPE_CLASS_NUMBER);
        port.setText(String.valueOf(p.getInt("port", 4712)));

        final EditText pass = new EditText(this);
        pass.setHint("Password connessioni esterne");
        pass.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        pass.setText(p.getString("pass", ""));

        final CheckBox show = new CheckBox(this);
        show.setText("Mostra password");
        show.setOnCheckedChangeListener((b, checked) -> {
            int sel = pass.getSelectionEnd();
            pass.setInputType(InputType.TYPE_CLASS_TEXT | (checked
                    ? InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                    : InputType.TYPE_TEXT_VARIATION_PASSWORD));
            if (sel >= 0) pass.setSelection(sel);
        });

        box.addView(host);
        box.addView(port);
        box.addView(pass);
        box.addView(show);

        new AlertDialog.Builder(this)
                .setTitle("Connessione ad aMule")
                .setView(box)
                .setPositiveButton("Salva", (d, w) -> {
                    int pt = 4712;
                    try {
                        pt = Integer.parseInt(port.getText().toString().trim());
                    } catch (Exception ignored) {
                    }
                    String hostClean = cleanHost(host.getText().toString());
                    int hp = hostPort(host.getText().toString());
                    if (hp > 0) pt = hp;
                    prefs().edit()
                            .putString("host", hostClean)
                            .putInt("port", pt)
                            .putString("pass", pass.getText().toString())
                            .apply();
                    updateStatusIdle();
                })
                .setNegativeButton("Annulla", null)
                .show();
    }

    private void updateStatusIdle() {
        SharedPreferences p = prefs();
        String h = p.getString("host", "");
        if (h.isEmpty()) {
            tvStatus.setText("Imposta l'indirizzo di aMule (menu ⋮ > Impostazioni)");
        } else {
            tvStatus.setText("aMule: " + h + ":" + p.getInt("port", 4712));
        }
    }

    // ---------------------------------------------------------------- ricerca

    private long parseSize(EditText ed, Spinner unit) {
        String s = ed.getText().toString().trim().replace(',', '.');
        if (s.isEmpty()) return 0;
        try {
            double v = Double.parseDouble(s);
            return (long) (v * UNIT_MULT[unit.getSelectedItemPosition()]);
        } catch (Exception e) {
            return 0;
        }
    }

    private void startSearch() {
        final String query = edQuery.getText().toString().trim();
        if (query.isEmpty()) {
            edQuery.setError("Scrivi cosa cercare");
            return;
        }
        SharedPreferences p = prefs();
        final String host = cleanHost(p.getString("host", ""));
        final int port = p.getInt("port", 4712);
        final String pass = p.getString("pass", "");
        if (host.isEmpty()) {
            showSettings();
            return;
        }

        InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
        if (imm != null) imm.hideSoftInputFromWindow(edQuery.getWindowToken(), 0);

        final int searchType = TYPE_VALUES[spType.getSelectedItemPosition()];
        final String fileType = FILE_VALUES[spFileType.getSelectedItemPosition()];
        String extRaw = edExt.getText().toString().trim();
        if (extRaw.startsWith(".")) extRaw = extRaw.substring(1);
        final String ext = extRaw;
        long av = 0;
        try {
            av = Long.parseLong(edAvail.getText().toString().trim());
        } catch (Exception ignored) {
        }
        final long avail = av;
        final long minSize = parseSize(edMin, spMinUnit);
        final long maxSize = parseSize(edMax, spMaxUnit);

        running = true;
        stopRequested = false;
        results.clear();
        adapter.notifyDataSetChanged();
        tvCount.setText("");
        btnSearch.setText("Stop");
        tvStatus.setText("Connessione a " + host + ":" + port + "...");

        new Thread(() -> runSearch(host, port, pass, searchType, query, fileType, ext, avail, minSize, maxSize)).start();
    }

    private void runSearch(String host, int port, String pass, int searchType, String query,
                           String fileType, String ext, long avail, long minSize, long maxSize) {
        EcClient ec = new EcClient();
        String error = null;
        try {
            String ver = ec.connect(host, port, pass);
            setStatus("Connesso" + (ver.isEmpty() ? "" : " (aMule " + ver + ")") + " - ricerca in corso...");
            ec.startSearch(searchType, query, fileType, ext, avail, minSize, maxSize);

            long t0 = System.currentTimeMillis();
            boolean seenProgress = false;
            while (!stopRequested) {
                Thread.sleep(1500);
                long prog = ec.progress();
                List<EcClient.Result> list = ec.results();
                publish(list, prog);

                long elapsed = System.currentTimeMillis() - t0;
                if (prog > 0 && prog != 0xFFFE) seenProgress = true;
                if (searchType == EcClient.SEARCH_KAD) {
                    if (prog == 0xFFFE) break;
                } else {
                    if (prog >= 100) break;
                    if (prog == 0 && (seenProgress || elapsed > 6000)) break;
                }
                if (elapsed > 120000) break;
            }
            if (stopRequested) {
                try {
                    ec.stopSearch();
                } catch (Exception ignored) {
                }
            }
            List<EcClient.Result> last = ec.results();
            publish(last, -1);
        } catch (Exception e) {
            if (e instanceof java.net.UnknownHostException) {
                error = "indirizzo non valido (" + host + "). Usa solo l'IP, es. 192.168.0.111";
            } else if (e instanceof java.net.ConnectException || e instanceof java.net.SocketTimeoutException
                    && e.getMessage() != null && e.getMessage().toLowerCase().contains("connect")) {
                error = "impossibile connettersi a " + host + ":" + port
                        + ". Controlla che aMule abbia le connessioni esterne attive e la porta EC " + port + " raggiungibile";
            } else if (e instanceof java.io.EOFException) {
                error = "connessione chiusa da aMule (porta sbagliata o accesso non consentito)";
            } else {
                error = e.getMessage() == null ? e.toString() : e.getMessage();
            }
        } finally {
            ec.close();
        }

        final String err = error;
        runOnUiThread(() -> {
            running = false;
            btnSearch.setEnabled(true);
            btnSearch.setText("Cerca");
            if (err != null) {
                tvStatus.setText("Errore: " + err);
            } else {
                tvStatus.setText("Ricerca terminata - " + results.size() + " risultati");
            }
        });
    }

    private void setStatus(final String s) {
        runOnUiThread(() -> tvStatus.setText(s));
    }

    private void publish(final List<EcClient.Result> list, final long progress) {
        final List<EcClient.Result> copy = new ArrayList<>(list);
        Collections.sort(copy, new Comparator<EcClient.Result>() {
            @Override
            public int compare(EcClient.Result a, EcClient.Result b) {
                return Long.compare(b.sources, a.sources);
            }
        });
        runOnUiThread(() -> {
            results.clear();
            results.addAll(copy);
            adapter.notifyDataSetChanged();
            tvCount.setText(copy.size() + " risultati");
            if (progress >= 0 && running) {
                String pr = (progress > 0 && progress <= 100) ? " (" + progress + "%)" : "";
                tvStatus.setText("Ricerca in corso" + pr + "...");
            }
        });
    }

    private void startDownload(final EcClient.Result r) {
        SharedPreferences p = prefs();
        final String host = cleanHost(p.getString("host", ""));
        final int port = p.getInt("port", 4712);
        final String pass = p.getString("pass", "");
        if (r.hash.length() != 32) {
            Toast.makeText(this, "Hash non disponibile", Toast.LENGTH_SHORT).show();
            return;
        }
        Toast.makeText(this, "Avvio download...", Toast.LENGTH_SHORT).show();
        new Thread(() -> {
            EcClient ec = new EcClient();
            String msg;
            try {
                ec.connect(host, port, pass);
                ec.download(r.hash);
                msg = "Download avviato: " + r.name;
            } catch (Exception e) {
                msg = "Errore download: " + (e.getMessage() == null ? e.toString() : e.getMessage());
            } finally {
                ec.close();
            }
            final String m = msg;
            runOnUiThread(() -> Toast.makeText(MainActivity.this, m, Toast.LENGTH_LONG).show());
        }).start();
    }

    // ---------------------------------------------------------------- lista

    private static String humanSize(long b) {
        if (b < 1024) return b + " B";
        double v = b;
        String[] u = {"KiB", "MiB", "GiB", "TiB"};
        int i = -1;
        while (v >= 1024 && i < u.length - 1) {
            v /= 1024;
            i++;
        }
        return String.format(Locale.ITALY, "%.2f %s", v, u[i]);
    }

    private class ResultAdapter extends BaseAdapter {
        @Override
        public int getCount() {
            return results.size();
        }

        @Override
        public Object getItem(int i) {
            return results.get(i);
        }

        @Override
        public long getItemId(int i) {
            return i;
        }

        @Override
        public View getView(int i, View convert, ViewGroup parent) {
            if (convert == null) {
                convert = LayoutInflater.from(MainActivity.this).inflate(R.layout.row_result, parent, false);
            }
            final EcClient.Result r = results.get(i);
            ((TextView) convert.findViewById(R.id.tvName)).setText(r.name);
            ((TextView) convert.findViewById(R.id.tvSize)).setText(humanSize(r.size));
            ((TextView) convert.findViewById(R.id.tvSources)).setText("Fonti: " + r.sources + " (" + r.complete + ")");
            Button bd = convert.findViewById(R.id.btnDownload);
            bd.setOnClickListener(v -> startDownload(r));
            return convert;
        }
    }
}
