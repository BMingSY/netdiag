package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type routeInfo struct {
	Gateway string
	IFace   string
	Source  string
}

type target struct {
	Role string
	Name string
	Host string
}

type sample struct {
	Round     int
	Time      time.Time
	Role      string
	Name      string
	Host      string
	OK        bool
	RTTMillis float64
	Error     string
}

type stats struct {
	Role      string
	Name      string
	Host      string
	Sent      int
	OK        int
	LossPct   float64
	Avg       float64
	Min       float64
	Max       float64
	P95       float64
	JitterAvg float64
}

type wifiInfo struct {
	IFace   string
	IsWiFi  bool
	Quality string
	Level   string
	Noise   string
	State   string
}

type reportData struct {
	GeneratedAt time.Time
	CSVPath     string
	Route       routeInfo
	RouteError  string
	WiFi        wifiInfo
	Targets     []target
	Summary     []stats
	Diagnosis   []string
	Samples     []sample
	Duration    time.Duration
	Interval    time.Duration
	Timeout     time.Duration
	MaxP95      float64
}

var timeRE = regexp.MustCompile(`time[=<]([0-9.]+)\s*ms`)

func main() {
	var (
		duration     = flag.Duration("duration", 5*time.Minute, "total time to run, for example 2m, 10m, 1h")
		interval     = flag.Duration("interval", time.Second, "interval between rounds")
		timeout      = flag.Duration("timeout", time.Second, "timeout for one ping")
		routerFlag   = flag.String("router", "auto", "router/default gateway IP, or auto")
		modemFlag    = flag.String("modem", "", "optical modem/ONT IP, for example 192.168.1.1; optional")
		ispFlag      = flag.String("isp", "", "ISP gateway/BRAS IP; optional, use traceroute/mtr to find it")
		internetFlag = flag.String("internet", "223.5.5.5,119.29.29.29,8.8.8.8", "comma-separated public targets")
		outFlag      = flag.String("out", "", "CSV output path, default ./result/netdiag-<timestamp>.csv")
		htmlFlag     = flag.String("html", "", "HTML report path, default is CSV path with .html")
	)
	flag.Parse()

	route, routeErr := detectDefaultRoute()
	if routeErr != nil && *routerFlag == "auto" {
		exitf("cannot detect default gateway: %v; pass -router <ip>", routeErr)
	}

	router := strings.TrimSpace(*routerFlag)
	if router == "auto" {
		router = route.Gateway
	}
	if net.ParseIP(router) == nil {
		exitf("invalid router IP %q", router)
	}

	targets := buildTargets(router, *modemFlag, *ispFlag, *internetFlag)
	if len(targets) == 0 {
		exitf("no targets to test")
	}

	outPath := *outFlag
	if outPath == "" {
		outPath = filepath.Join("result", fmt.Sprintf("netdiag-%s.csv", time.Now().Format("20060102-150405")))
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		exitf("create output dir: %v", err)
	}

	file, err := os.Create(outPath)
	if err != nil {
		exitf("create csv: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()
	mustWrite(writer, []string{"round", "timestamp", "role", "name", "host", "ok", "rtt_ms", "error"})

	wifi := inspectWiFi(route.IFace)
	printHeader(route, routeErr, wifi, targets, outPath, *duration, *interval, *timeout)

	all := runMonitor(targets, *duration, *interval, *timeout, writer)
	summary := summarize(all)
	diagnosis := diagnose(summary, wifi)

	fmt.Println()
	fmt.Println("Summary")
	fmt.Println("-------")
	for _, s := range summary {
		fmt.Printf("%-16s %-18s host=%-15s sent=%d ok=%d loss=%.1f%% avg=%.1fms p95=%.1fms max=%.1fms jitter=%.1fms\n",
			s.Role, s.Name, s.Host, s.Sent, s.OK, s.LossPct, s.Avg, s.P95, s.Max, s.JitterAvg)
	}

	fmt.Println()
	fmt.Println("Diagnosis")
	fmt.Println("---------")
	for _, line := range diagnosis {
		fmt.Println(line)
	}

	htmlPath := *htmlFlag
	if htmlPath == "" {
		htmlPath = strings.TrimSuffix(outPath, filepath.Ext(outPath)) + ".html"
	}
	if err := writeHTMLReport(htmlPath, reportData{
		GeneratedAt: time.Now(),
		CSVPath:     outPath,
		Route:       route,
		RouteError:  errorString(routeErr),
		WiFi:        wifi,
		Targets:     targets,
		Summary:     summary,
		Diagnosis:   diagnosis,
		Samples:     all,
		Duration:    *duration,
		Interval:    *interval,
		Timeout:     *timeout,
	}); err != nil {
		exitf("write html report: %v", err)
	}

	fmt.Println()
	fmt.Printf("CSV saved to %s\n", outPath)
	fmt.Printf("HTML report saved to %s\n", htmlPath)
}

func buildTargets(router, modem, isp, internet string) []target {
	var targets []target
	add := func(role, name, host string) {
		host = strings.TrimSpace(host)
		if host == "" {
			return
		}
		targets = append(targets, target{Role: role, Name: name, Host: host})
	}

	add("pc_wifi_router", "router", router)
	add("router_modem", "modem", modem)
	add("modem_isp", "isp_gateway", isp)

	for _, host := range splitCSV(internet) {
		add("internet", host, host)
	}
	return targets
}

func runMonitor(targets []target, duration, interval, timeout time.Duration, writer *csv.Writer) []sample {
	deadline := time.Now().Add(duration)
	round := 0
	var all []sample

	for {
		now := time.Now()
		if round > 0 && !now.Before(deadline) {
			break
		}
		round++

		results := pingRound(targets, timeout)
		for i := range results {
			results[i].Round = round
		}
		sort.SliceStable(results, func(i, j int) bool {
			if results[i].Role == results[j].Role {
				return results[i].Name < results[j].Name
			}
			return roleRank(results[i].Role) < roleRank(results[j].Role)
		})

		for _, r := range results {
			all = append(all, r)
			rtt := ""
			if r.OK {
				rtt = fmt.Sprintf("%.3f", r.RTTMillis)
			}
			mustWrite(writer, []string{
				strconv.Itoa(r.Round),
				r.Time.Format(time.RFC3339),
				r.Role,
				r.Name,
				r.Host,
				strconv.FormatBool(r.OK),
				rtt,
				r.Error,
			})
		}
		writer.Flush()

		fmt.Printf("round %-4d", round)
		for _, r := range results {
			if r.OK {
				fmt.Printf(" | %s %.1fms", shortName(r), r.RTTMillis)
			} else {
				fmt.Printf(" | %s loss", shortName(r))
			}
		}
		fmt.Println()

		next := now.Add(interval)
		sleep := time.Until(next)
		if sleep <= 0 {
			sleep = 10 * time.Millisecond
		}
		if time.Now().Add(sleep).After(deadline) {
			break
		}
		time.Sleep(sleep)
	}

	return all
}

func pingRound(targets []target, timeout time.Duration) []sample {
	results := make([]sample, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t target) {
			defer wg.Done()
			rtt, err := pingOnce(t.Host, timeout)
			s := sample{
				Time: time.Now(),
				Role: t.Role,
				Name: t.Name,
				Host: t.Host,
				OK:   err == nil,
			}
			if err == nil {
				s.RTTMillis = rtt
			} else {
				s.Error = err.Error()
			}
			results[i] = s
		}(i, t)
	}
	wg.Wait()
	return results
}

func pingOnce(host string, timeout time.Duration) (float64, error) {
	seconds := int(math.Ceil(timeout.Seconds()))
	if seconds < 1 {
		seconds = 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout+1500*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ping", "-n", "-c", "1", "-W", strconv.Itoa(seconds), host)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	text := out.String()
	if ctx.Err() != nil {
		return 0, errors.New("command timeout")
	}
	if err != nil {
		return 0, compactError(text, err)
	}

	m := timeRE.FindStringSubmatch(text)
	if len(m) != 2 {
		return 0, fmt.Errorf("no rtt in ping output")
	}
	rtt, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, fmt.Errorf("parse rtt: %w", err)
	}
	return rtt, nil
}

func summarize(samples []sample) []stats {
	byKey := make(map[string][]sample)
	var keys []string
	for _, s := range samples {
		key := s.Role + "\x00" + s.Name + "\x00" + s.Host
		if _, ok := byKey[key]; !ok {
			keys = append(keys, key)
		}
		byKey[key] = append(byKey[key], s)
	}

	var result []stats
	for _, key := range keys {
		items := byKey[key]
		parts := strings.Split(key, "\x00")
		st := stats{Role: parts[0], Name: parts[1], Host: parts[2], Sent: len(items)}
		var values []float64
		for _, item := range items {
			if item.OK {
				st.OK++
				values = append(values, item.RTTMillis)
			}
		}
		st.LossPct = lossPct(st.Sent, st.OK)
		fillRTTStats(&st, values)
		result = append(result, st)
	}

	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Role == result[j].Role {
			return result[i].Name < result[j].Name
		}
		return roleRank(result[i].Role) < roleRank(result[j].Role)
	})
	return result
}

func fillRTTStats(st *stats, values []float64) {
	if len(values) == 0 {
		return
	}
	if len(values) > 1 {
		var diffSum float64
		for i := 1; i < len(values); i++ {
			diffSum += math.Abs(values[i] - values[i-1])
		}
		st.JitterAvg = diffSum / float64(len(values)-1)
	}

	sort.Float64s(values)
	st.Min = values[0]
	st.Max = values[len(values)-1]
	var sum float64
	for _, v := range values {
		sum += v
	}
	st.Avg = sum / float64(len(values))
	st.P95 = percentile(values, 0.95)
}

func diagnose(summary []stats, wifi wifiInfo) []string {
	var lines []string
	router := firstRole(summary, "pc_wifi_router")
	modem := firstRole(summary, "router_modem")
	isp := firstRole(summary, "modem_isp")
	internet := aggregateInternet(summary)

	if wifi.IsWiFi {
		lines = append(lines, fmt.Sprintf("- WiFi interface: %s state=%s quality=%s level=%s noise=%s", wifi.IFace, blank(wifi.State, "unknown"), blank(wifi.Quality, "unknown"), blank(wifi.Level, "unknown"), blank(wifi.Noise, "unknown")))
	}

	if router == nil {
		lines = append(lines, "- Cannot judge PC -> WiFi/router: router target was not measured.")
		return lines
	}

	if badLocal(*router) {
		lines = append(lines, fmt.Sprintf("- Most suspicious: PC -> WiFi/router. Router loss %.1f%%, p95 %.1fms. If this target is your default gateway, upstream results are secondary until this is stable.", router.LossPct, router.P95))
		if wifi.IsWiFi && weakWiFi(wifi) {
			lines = append(lines, "- WiFi signal also looks weak from /proc/net/wireless; move closer, switch 5 GHz/2.4 GHz, change channel, or test wired Ethernet.")
		}
		return lines
	}
	lines = append(lines, fmt.Sprintf("- PC -> WiFi/router looks OK: router loss %.1f%%, p95 %.1fms.", router.LossPct, router.P95))

	if modem != nil {
		if worseThan(*modem, *router, 2.0, 10) {
			lines = append(lines, fmt.Sprintf("- Most suspicious: router -> optical modem/ONT. Modem loss %.1f%% vs router %.1f%%, p95 increase %.1fms.", modem.LossPct, router.LossPct, modem.P95-router.P95))
			return lines
		}
		lines = append(lines, fmt.Sprintf("- Router -> optical modem/ONT looks OK: modem loss %.1f%%, p95 %.1fms.", modem.LossPct, modem.P95))
	} else {
		lines = append(lines, "- Optical modem/ONT was not measured. Add -modem <光猫管理IP> if your router can reach it.")
	}

	base := router
	if modem != nil {
		base = modem
	}
	if isp != nil {
		if worseThan(*isp, *base, 2.0, 20) {
			lines = append(lines, fmt.Sprintf("- Most suspicious: optical modem -> ISP access network. ISP gateway loss %.1f%%, p95 increase %.1fms over previous hop.", isp.LossPct, isp.P95-base.P95))
			return lines
		}
		lines = append(lines, fmt.Sprintf("- ISP access target looks OK: loss %.1f%%, p95 %.1fms.", isp.LossPct, isp.P95))
		base = isp
	} else {
		lines = append(lines, "- ISP gateway was not measured. Add -isp <运营商第一跳/BRAS IP> for a cleaner modem -> ISP judgment.")
	}

	if internet != nil {
		if worseThan(*internet, *base, 3.0, 30) {
			lines = append(lines, fmt.Sprintf("- Most suspicious: ISP/backbone/public internet path. Public targets loss %.1f%%, p95 %.1fms; previous hop p95 %.1fms.", internet.LossPct, internet.P95, base.P95))
		} else {
			lines = append(lines, fmt.Sprintf("- Public internet path looks OK during this run: loss %.1f%%, p95 %.1fms.", internet.LossPct, internet.P95))
		}
	}

	if len(lines) == 0 {
		lines = append(lines, "- Not enough data to diagnose.")
	}
	return lines
}

func writeHTMLReport(path string, data reportData) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	for _, s := range data.Summary {
		if s.P95 > data.MaxP95 {
			data.MaxP95 = s.P95
		}
	}
	if data.MaxP95 < 1 {
		data.MaxP95 = 1
	}

	funcs := template.FuncMap{
		"ms": func(v float64) string {
			if v == 0 {
				return "-"
			}
			return fmt.Sprintf("%.1f", v)
		},
		"pct": func(v float64) string {
			return fmt.Sprintf("%.1f%%", v)
		},
		"dur": func(v time.Duration) string {
			return v.String()
		},
		"ts": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05")
		},
		"health": healthClass,
		"bar": func(v, max float64) string {
			if max <= 0 || v <= 0 {
				return "0"
			}
			width := v / max * 100
			if width < 2 {
				width = 2
			}
			if width > 100 {
				width = 100
			}
			return fmt.Sprintf("%.1f", width)
		},
		"rtt": func(s sample) string {
			if !s.OK {
				return "loss"
			}
			return fmt.Sprintf("%.1f ms", s.RTTMillis)
		},
		"sampleClass": func(s sample) string {
			if !s.OK {
				return "bad"
			}
			if s.RTTMillis >= 100 {
				return "bad"
			}
			if s.RTTMillis >= 40 {
				return "warn"
			}
			return "good"
		},
	}

	t, err := template.New("report").Funcs(funcs).Parse(reportTemplate)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return t.Execute(f, data)
}

func healthClass(s stats) string {
	if s.LossPct >= 5 || s.P95 >= 100 {
		return "bad"
	}
	if s.LossPct >= 1 || s.P95 >= 40 || s.JitterAvg >= 15 {
		return "warn"
	}
	return "good"
}

const reportTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network Diagnostic Report</title>
<style>
:root { color-scheme: light; --bg:#f6f7f9; --panel:#fff; --text:#1f2937; --muted:#667085; --line:#d9dee7; --good:#147a3d; --good-bg:#e9f7ef; --warn:#9a5b00; --warn-bg:#fff4d6; --bad:#b42318; --bad-bg:#fde8e7; --blue:#2563eb; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 14px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
main { max-width: 1180px; margin: 0 auto; padding: 24px; }
h1 { margin: 0 0 4px; font-size: 28px; letter-spacing: 0; }
h2 { margin: 28px 0 10px; font-size: 18px; letter-spacing: 0; }
.muted { color: var(--muted); }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; }
.grid { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); }
.metric { border: 1px solid var(--line); border-radius: 8px; padding: 12px; background: #fff; }
.metric .label { color: var(--muted); font-size: 12px; }
.metric .value { margin-top: 4px; font-size: 18px; font-weight: 650; }
ul { margin: 0; padding-left: 20px; }
table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }
th, td { padding: 9px 10px; border-bottom: 1px solid var(--line); text-align: left; white-space: nowrap; }
th { background: #eef1f5; font-size: 12px; color: #475467; }
tr:last-child td { border-bottom: 0; }
.status { display: inline-block; min-width: 58px; padding: 3px 8px; border-radius: 999px; font-size: 12px; font-weight: 650; text-align: center; }
.good .status, .status.good { color: var(--good); background: var(--good-bg); }
.warn .status, .status.warn { color: var(--warn); background: var(--warn-bg); }
.bad .status, .status.bad { color: var(--bad); background: var(--bad-bg); }
.barcell { min-width: 160px; }
.bartrack { height: 8px; width: 100%; border-radius: 999px; background: #e5e7eb; overflow: hidden; }
.barfill { height: 100%; border-radius: 999px; background: var(--blue); }
.samples { max-height: 560px; overflow: auto; border: 1px solid var(--line); border-radius: 8px; }
.samples table { border: 0; border-radius: 0; }
.samples th { position: sticky; top: 0; z-index: 1; }
code { background: #eef1f5; border-radius: 4px; padding: 1px 4px; }
@media (max-width: 720px) {
  main { padding: 14px; }
  table { font-size: 12px; }
  th, td { padding: 7px 8px; }
  .tablewrap { overflow-x: auto; }
}
</style>
</head>
<body>
<main>
  <h1>Network Diagnostic Report</h1>
  <div class="muted">Generated at {{ts .GeneratedAt}} · CSV <code>{{.CSVPath}}</code></div>

  <h2>Run Info</h2>
  <section class="grid">
    <div class="metric"><div class="label">Default gateway</div><div class="value">{{if .Route.Gateway}}{{.Route.Gateway}}{{else}}unknown{{end}}</div></div>
    <div class="metric"><div class="label">Interface</div><div class="value">{{if .Route.IFace}}{{.Route.IFace}}{{else}}unknown{{end}}</div></div>
    <div class="metric"><div class="label">Duration</div><div class="value">{{dur .Duration}}</div></div>
    <div class="metric"><div class="label">Interval / timeout</div><div class="value">{{dur .Interval}} / {{dur .Timeout}}</div></div>
  </section>

  {{if .RouteError}}<p class="panel">Route detection error: {{.RouteError}}</p>{{end}}

  <h2>Diagnosis</h2>
  <section class="panel">
    <ul>{{range .Diagnosis}}<li>{{.}}</li>{{end}}</ul>
  </section>

  <h2>Targets</h2>
  <div class="tablewrap">
    <table>
      <thead><tr><th>Layer</th><th>Name</th><th>Host</th></tr></thead>
      <tbody>{{range .Targets}}<tr><td>{{.Role}}</td><td>{{.Name}}</td><td>{{.Host}}</td></tr>{{end}}</tbody>
    </table>
  </div>

  <h2>Summary</h2>
  <div class="tablewrap">
    <table>
      <thead>
        <tr><th>Status</th><th>Layer</th><th>Name</th><th>Host</th><th>Sent</th><th>OK</th><th>Loss</th><th>Avg ms</th><th>P95 ms</th><th>Max ms</th><th>Jitter ms</th><th>P95 bar</th></tr>
      </thead>
      <tbody>
      {{range .Summary}}
        <tr class="{{health .}}">
          <td><span class="status {{health .}}">{{health .}}</span></td>
          <td>{{.Role}}</td><td>{{.Name}}</td><td>{{.Host}}</td><td>{{.Sent}}</td><td>{{.OK}}</td><td>{{pct .LossPct}}</td>
          <td>{{ms .Avg}}</td><td>{{ms .P95}}</td><td>{{ms .Max}}</td><td>{{ms .JitterAvg}}</td>
          <td class="barcell"><div class="bartrack"><div class="barfill" style="width: {{bar .P95 $.MaxP95}}%"></div></div></td>
        </tr>
      {{end}}
      </tbody>
    </table>
  </div>

  <h2>Samples</h2>
  <div class="samples">
    <table>
      <thead><tr><th>Round</th><th>Time</th><th>Layer</th><th>Name</th><th>Host</th><th>Result</th><th>Error</th></tr></thead>
      <tbody>
      {{range .Samples}}
        <tr class="{{sampleClass .}}">
          <td>{{.Round}}</td><td>{{ts .Time}}</td><td>{{.Role}}</td><td>{{.Name}}</td><td>{{.Host}}</td><td><span class="status {{sampleClass .}}">{{rtt .}}</span></td><td>{{.Error}}</td>
        </tr>
      {{end}}
      </tbody>
    </table>
  </div>
</main>
</body>
</html>`

func detectDefaultRoute() (routeInfo, error) {
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return routeInfo{}, err
	}
	fields := strings.Fields(string(out))
	var r routeInfo
	r.Source = strings.TrimSpace(string(out))
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "via":
			if i+1 < len(fields) {
				r.Gateway = fields[i+1]
			}
		case "dev":
			if i+1 < len(fields) {
				r.IFace = fields[i+1]
			}
		}
	}
	if r.Gateway == "" {
		return r, fmt.Errorf("default route has no gateway: %s", strings.TrimSpace(string(out)))
	}
	return r, nil
}

func inspectWiFi(iface string) wifiInfo {
	info := wifiInfo{IFace: iface}
	if iface == "" {
		return info
	}

	if state, err := os.ReadFile(filepath.Join("/sys/class/net", iface, "operstate")); err == nil {
		info.State = strings.TrimSpace(string(state))
	}
	if _, err := os.Stat(filepath.Join("/sys/class/net", iface, "wireless")); err == nil {
		info.IsWiFi = true
	}

	data, err := os.ReadFile("/proc/net/wireless")
	if err != nil {
		return info
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, iface+":") {
			continue
		}
		info.IsWiFi = true
		fields := strings.Fields(strings.ReplaceAll(line, ".", ""))
		if len(fields) >= 5 {
			info.Quality = fields[2]
			info.Level = fields[3]
			info.Noise = fields[4]
		}
	}
	return info
}

func weakWiFi(w wifiInfo) bool {
	level, err := strconv.ParseFloat(w.Level, 64)
	if err != nil {
		return false
	}
	return level < -70 || level < 35
}

func aggregateInternet(summary []stats) *stats {
	var sent, ok int
	var values []float64
	for _, s := range summary {
		if s.Role != "internet" {
			continue
		}
		sent += s.Sent
		ok += s.OK
		if s.OK > 0 {
			values = append(values, s.P95)
		}
	}
	if sent == 0 {
		return nil
	}
	st := stats{Role: "internet", Name: "public_targets", Host: "multiple", Sent: sent, OK: ok, LossPct: lossPct(sent, ok)}
	fillRTTStats(&st, values)
	return &st
}

func firstRole(summary []stats, role string) *stats {
	for _, s := range summary {
		if s.Role == role {
			cp := s
			return &cp
		}
	}
	return nil
}

func badLocal(s stats) bool {
	return s.LossPct >= 1 || s.P95 >= 20 || s.JitterAvg >= 8
}

func worseThan(later, earlier stats, lossDelta, p95Delta float64) bool {
	return later.LossPct-earlier.LossPct >= lossDelta || later.P95-earlier.P95 >= p95Delta || later.LossPct >= 5
}

func lossPct(sent, ok int) float64 {
	if sent == 0 {
		return 0
	}
	return float64(sent-ok) * 100 / float64(sent)
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	pos := p * float64(len(sorted)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return sorted[lo]
	}
	weight := pos - float64(lo)
	return sorted[lo]*(1-weight) + sorted[hi]*weight
}

func printHeader(route routeInfo, routeErr error, wifi wifiInfo, targets []target, out string, duration, interval, timeout time.Duration) {
	fmt.Println("Network diagnostic monitor")
	fmt.Println("--------------------------")
	if routeErr == nil {
		fmt.Printf("default route: gateway=%s iface=%s\n", route.Gateway, route.IFace)
	} else {
		fmt.Printf("default route: unavailable (%v)\n", routeErr)
	}
	if wifi.IFace != "" {
		fmt.Printf("interface: %s state=%s wifi=%v quality=%s level=%s noise=%s\n", wifi.IFace, blank(wifi.State, "unknown"), wifi.IsWiFi, blank(wifi.Quality, "unknown"), blank(wifi.Level, "unknown"), blank(wifi.Noise, "unknown"))
	}
	fmt.Printf("duration=%v interval=%v timeout=%v output=%s\n", duration, interval, timeout, out)
	fmt.Println("targets:")
	for _, t := range targets {
		fmt.Printf("  %-16s %-14s %s\n", t.Role, t.Name, t.Host)
	}
	fmt.Println()
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func roleRank(role string) int {
	switch role {
	case "pc_wifi_router":
		return 1
	case "router_modem":
		return 2
	case "modem_isp":
		return 3
	case "internet":
		return 4
	default:
		return 99
	}
}

func shortName(s sample) string {
	switch s.Role {
	case "pc_wifi_router":
		return "router"
	case "router_modem":
		return "modem"
	case "modem_isp":
		return "isp"
	default:
		return s.Name
	}
}

func compactError(output string, err error) error {
	text := strings.TrimSpace(output)
	if text == "" {
		return err
	}
	lines := strings.Split(text, "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	if strings.Contains(text, "100% packet loss") {
		return errors.New("packet loss")
	}
	if last != "" {
		return errors.New(last)
	}
	return err
}

func mustWrite(w *csv.Writer, row []string) {
	if err := w.Write(row); err != nil {
		exitf("write csv: %v", err)
	}
}

func blank(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
