#!/usr/bin/env python3
"""Verified-findings checker.

Usage: python3 plearun_cli.py REPORT RECORDS_DIR > findings.json

Offline and deterministic (no network, no LLM). Pipeline:
  1. load records into one row model (encoding / format tolerant)
  2. estimate clock offsets from events seen in >=2 sources (else: do not align)
  3. extract claims from the report
  4. decide each claim conservatively from candidate rows
  5. verify every cite/quote against the raw row text before writing it
Row numbering: CSV = 1-based data-row index (marker/comment/header/blank lines
not counted); JSON = 1-based index of event objects in document order;
VTT = 1-based cue index.
"""
import csv, io, json, os, re, sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from statistics import median

try:
    csv.field_size_limit(2 ** 31 - 1)
except OverflowError:
    csv.field_size_limit(10 ** 9)

UNALIGNED_UNC = 600.0   # seconds of clock error we must assume for a device we could not align
HEDGE_S = 90.0          # extra tolerance for "about / around / roughly"
SENTINEL_UNC = 5.0      # residual uncertainty of an aligned clock

# ----------------------------------------------------------------- time parsing
ISO = re.compile(r'^(\d{4})-(\d{2})-(\d{2})[T ](\d{1,2}):(\d{2})(?::(\d{2})(?:[.,]\d+)?)?\s*(Z|[+-]\d{2}:?\d{2})?$')
CLOCK = re.compile(r'^(\d{1,2}):(\d{2})(?::(\d{2}))?$')
TIME_RX = re.compile(r'(?<![\d:.])([01]?\d|2[0-3]):([0-5]\d)(?::([0-5]\d))?(?![\d:])(?:\s*([ap])\.?m\.?)?', re.I)
OFFSET_RX = re.compile(r'\d{2}:\d{2}(?::\d{2})?(?:[.,]\d+)?(Z|[+-]\d{2}:\d{2})(?![\d:])')
DATE_RX = re.compile(r'\b(\d{4}-\d{2}-\d{2})\b')


def tzoff(s):
    if s is None:
        return None
    if s == 'Z':
        return 0
    sign = -1 if s[0] == '-' else 1
    d = s[1:].replace(':', '')
    return sign * (int(d[:2]) * 3600 + int(d[2:]) * 60)


def epoch_of(date, h, m, s, off):
    y, mo, d = (int(x) for x in date.split('-'))
    return datetime(y, mo, d, h, m, s, tzinfo=timezone.utc).timestamp() - off


def parse_ts(v, date, local):
    """-> (epoch_seconds, resolution_seconds, explicit_tz) or None."""
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    s = str(v).strip()
    try:
        if re.fullmatch(r'\d{13}', s):
            e = int(s) / 1000.0
            return (e, 1, True) if 9.4e8 < e < 4.1e9 else None
        if re.fullmatch(r'\d{10}(\.\d+)?', s):
            e = float(s)
            return (e, 1, True) if 9.4e8 < e < 4.1e9 else None
        m = ISO.match(s)
        if m:
            y, mo, d, h, mi, sec, tz = m.groups()
            off = tzoff(tz)
            e = epoch_of('%s-%s-%s' % (y, mo, d), int(h), int(mi), int(sec or 0), local if off is None else off)
            return e, (1 if sec else 60), off is not None
        m = CLOCK.match(s)
        if m and date:
            h, mi, sec = int(m.group(1)), int(m.group(2)), m.group(3)
            if h > 23 or mi > 59:
                return None
            return epoch_of(date, h, mi, int(sec or 0), local), (1 if sec else 60), False
    except (ValueError, OverflowError):
        return None
    return None


# ------------------------------------------------------------------ text -> semantics
KIND_RX = [  # (kind, regex, strength)  s = states the event itself, w = only describes it
    ('call', re.compile(r'\b911\b|\bemergency call\b|\bcall (?:received|logged)\b'), 's'),
    ('call', re.compile(r'\bcaller\b|\bcalled in\b'), 'w'),
    ('stop', re.compile(r'\bstops?\b|\bstopp(?:ed|ing)\b|\bpull(?:ed|ing)\s+(?:in|over|into|off)\b|\bcame to a (?:stop|halt)\b|\bparked\b'), 's'),
    ('observe', re.compile(r'\bobserv(?:ed|ation)\b|\bspotted\b|\bsighted\b|\bfirst saw\b'), 's'),
    ('on_scene', re.compile(r'\bon[ -]scene\b|\barriv(?:ed|al)\b'), 's'),
    ('dispatch', re.compile(r'\bdispatched\b'), 's'),
]
SPEED_MPH = re.compile(r'(\d{2,3}(?:\.\d+)?)\s*(?:mph|mi/h|miles per hour)\b', re.I)
SPEED_IN = re.compile(r'\b(\d{2,3})\s+in\s+(?:a|an|the)\s+(\d{2,3})\b', re.I)
ZONE_RX = re.compile(r'(?:posted|zone of|limit of|speed limit)\D{0,10}?(\d{2,3})\b|\b(\d{2,3})\s*(?:mph\s*)?(?:zone|limit)\b', re.I)
HEDGE_RX = re.compile(r'\b(?:about|around|approx(?:imately)?|roughly|nearly|almost|circa)\b|~|\bor so\b', re.I)
AMBIG_RX = re.compile(r'\b(?:other|another|second|different|previous|earlier|prior|truck|motorcycle|bus)\b', re.I)
CAMERA_RX = re.compile(r'\bcamera\b|\bCAM-\w+|\bradar\b|\bspeed trap\b', re.I)


def classify(text):
    t = text.lower().replace('_', ' ')
    kinds = {}
    for k, rx, s in KIND_RX:
        if rx.search(t) and kinds.get(k) != 's':
            kinds[k] = s
    return kinds


def kind_of(text):
    """earliest-mentioned event kind in a claim clause"""
    t = text.lower().replace('_', ' ')
    best = None
    for k, rx, s in KIND_RX:
        m = rx.search(t)
        if m and (best is None or m.start() < best[0]):
            best = (m.start(), k)
    return best[1] if best else None


def extract_speeds(text):
    spans, out = [], []
    for m in SPEED_IN.finditer(text):
        out.append((float(m.group(1)), int(m.group(2))))
        spans.append(m.span())
    zone_spans, zone = [], None
    for m in ZONE_RX.finditer(text):
        z = m.group(1) or m.group(2)
        zone_spans.append(m.span())
        zone = zone if zone is not None else int(z)
    for m in SPEED_MPH.finditer(text):
        a, b = m.span()
        if any(a >= x and b <= y for x, y in spans + zone_spans):
            continue
        out.append((float(m.group(1)), zone))
    return out


# ------------------------------------------------------------------------ records
class Row:
    def __init__(self, **kw):
        self.file = self.src = self.raw = self.text = self.quote = self.device = self.zone = None
        self.n = 0
        self.t = None
        self.res = 60
        self.tcol = False      # time came from a time column/field (not mined from free text)
        self.hedge = 0.0
        self.kinds = {}
        self.speeds = []
        self.speed = None      # camera reading
        self.is_camera = False
        self.__dict__.update(kw)


def decode(b):
    if b.startswith((b'\xff\xfe', b'\xfe\xff')):
        try:
            return b.decode('utf-16')
        except UnicodeDecodeError:
            pass
    for enc in ('utf-8-sig', 'cp1252'):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            pass
    return b.decode('latin-1')


class Ctx:
    date = None
    local = 0


TIMECOLS = ('timestamp', 'time', 'logged', 'ts', 'datetime', 'date_time', 'when')
TIME_KEY = re.compile(r'(time|logged|stamp|^ts$|_at$|date)', re.I)


def finish_text_row(r, text):
    r.text = text
    r.kinds = classify(text)
    r.speeds = extract_speeds(text)


def load_csv(name, text, ctx):
    lines = re.split(r'\r\n|\r|\n', text)
    rd = csv.reader(io.StringIO(text, newline=''))
    header, prev, n, out = None, 0, 0, []
    try:
        for fields in rd:
            ln = rd.line_num
            raw = '\n'.join(lines[prev:ln])
            prev = ln
            if not any(f.strip() for f in fields) or fields[0].lstrip().startswith('#'):
                continue
            if header is None:
                header = [h.strip().lower() for h in fields]
                continue
            n += 1
            rec = dict(zip(header, fields))
            tcol = next((c for c in header if c in TIMECOLS), None)
            tv = parse_ts(rec.get(tcol), ctx.date, ctx.local) if tcol else None
            r = Row(file=name, n=n, raw=raw, quote=raw, src=name)
            if tv:
                r.t, r.res, r.tcol = tv[0], tv[1], True
            sp = None
            for c in ('speed_mph', 'speed', 'mph'):
                if c in rec:
                    try:
                        sp = float(rec[c])
                    except ValueError:
                        sp = None
            if sp is not None:
                r.is_camera, r.speed = True, sp
                r.device = (rec.get('device') or '').strip() or None
                r.src = '%s#%s' % (name, r.device)
                try:
                    r.zone = int(float(rec.get('zone_mph', '')))
                except ValueError:
                    pass
                r.text = raw
            else:
                finish_text_row(r, ' ; '.join(v for c, v in rec.items() if c != tcol and v))
            out.append(r)
    except csv.Error:
        pass
    return out


def load_json(name, text, ctx):
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return []
    stack, events = [data], []
    while stack:
        x = stack.pop()
        if isinstance(x, dict):
            tkey = next((k for k, v in x.items() if isinstance(k, str) and TIME_KEY.search(k)
                         and isinstance(v, (str, int, float)) and parse_ts(v, ctx.date, ctx.local)), None)
            if tkey:
                events.append((x, tkey))
            else:
                stack.extend(reversed(list(x.values())))
        elif isinstance(x, list):
            stack.extend(reversed(x))
    out = []
    for i, (x, tkey) in enumerate(events, 1):
        tv = parse_ts(x[tkey], ctx.date, ctx.local)
        raw = json.dumps(x, ensure_ascii=False) + '\n' + json.dumps(x, ensure_ascii=False, separators=(',', ':'))
        r = Row(file=name, n=i, raw=raw, src=name, t=tv[0], res=tv[1], tcol=True)
        frag = None
        for sep in (None, (',', ':')):
            cand = json.dumps({tkey: x[tkey]}, ensure_ascii=False, separators=sep)[1:-1]
            if cand in text:
                frag = cand
                break
        r.quote = frag
        finish_text_row(r, ' '.join(str(v) for k, v in x.items() if k != tkey and isinstance(v, (str, int, float))))
        out.append(r)
    return out


VTT_TIMING = re.compile(r'^\s*((?:\d+:)?\d{2}:\d{2}\.\d{3})\s*-->\s*((?:\d+:)?\d{2}:\d{2}\.\d{3})')
TAG_RX = re.compile(r'<[^>]*>')


def load_vtt(name, text, ctx):
    out, n = [], 0
    for block in re.split(r'\n[ \t]*\n', re.sub(r'\r\n|\r', '\n', text)):
        lines = block.split('\n')
        ti = next((i for i, l in enumerate(lines) if VTT_TIMING.match(l)), None)
        if ti is None:
            continue
        body = [l for l in lines[ti + 1:] if l.strip()]
        n += 1
        stripped = [TAG_RX.sub('', l) for l in body]
        r = Row(file=name, n=n, raw=lines[ti] + '\n' + '\n'.join(body), src=name)
        finish_text_row(r, ' '.join(stripped))
        pick = next((i for i, l in enumerate(stripped) if extract_speeds(l) or classify(l) or TIME_RX.search(l)), 0)
        r.quote = body[pick] if body else None
        m = TIME_RX.search(r.text)
        if m and ctx.date:   # a wall-clock time spoken in the cue: coarse, never "aligned"
            h = int(m.group(1)) % 12 + (12 if (m.group(4) or '').lower() == 'p' else 0) if m.group(4) else int(m.group(1))
            r.t = epoch_of(ctx.date, h, int(m.group(2)), int(m.group(3) or 0), ctx.local)
            r.res = 1 if m.group(3) else 60
            r.hedge = HEDGE_S if HEDGE_RX.search(r.text) else 0.0
        out.append(r)
    return out


def load_all(rec_dir, report_text):
    files = []
    for root, dirs, names in os.walk(rec_dir):
        dirs.sort()
        for fn in sorted(names):
            p = os.path.join(root, fn)
            try:
                with open(p, 'rb') as f:
                    files.append((os.path.relpath(p, rec_dir).replace(os.sep, '/'), decode(f.read())))
            except OSError as e:
                print('skip %s: %s' % (p, e), file=sys.stderr)
    ctx = Ctx()
    offs = Counter()
    dates = Counter()
    for _, t in files:
        offs.update(tzoff(x) for x in OFFSET_RX.findall(t))
        dates.update(DATE_RX.findall(t))
    ctx.local = offs.most_common(1)[0][0] if offs else 0
    m = DATE_RX.search(report_text)
    ctx.date = m.group(1) if m else (dates.most_common(1)[0][0] if dates else None)
    rows, texts = [], {}
    for name, t in files:
        texts[name] = t
        ext = name.lower().rsplit('.', 1)[-1]
        try:
            if ext in ('csv', 'tsv'):
                rows += load_csv(name, t, ctx)
            elif ext == 'json':
                rows += load_json(name, t, ctx)
            elif ext == 'vtt':
                rows += load_vtt(name, t, ctx)
        except Exception as e:  # one bad file must never sink the run
            print('skip %s: %s' % (name, e), file=sys.stderr)
    return rows, texts, ctx


# ---------------------------------------------------------------- clock alignment
class Align:
    def __init__(self):
        self.off, self.unc = {}, {}


def estimate_offsets(rows):
    """Offsets are estimated ONLY from events of the same kind that appear exactly once in each
    of two sources, and only trusted when >=2 such anchors agree. Otherwise: do not align."""
    by_kind = defaultdict(lambda: defaultdict(list))
    for r in rows:
        if r.tcol and r.t is not None and not r.is_camera:
            for k, s in r.kinds.items():
                if s == 's':
                    by_kind[k][r.src].append(r)
    edges = defaultdict(list)
    for k, srcs in by_kind.items():
        uniq = {s: v[0] for s, v in srcs.items() if len(v) == 1}
        names = sorted(uniq)
        for i, a in enumerate(names):
            for b in names[i + 1:]:
                edges[(a, b)].append((uniq[a].t - uniq[b].t, (uniq[a].res + uniq[b].res) / 2.0))
    adj = defaultdict(list)
    for (a, b), ds in sorted(edges.items()):
        if len(ds) < 2 or not all(abs(x[0] - y[0]) <= x[1] + y[1] + 15 for x in ds for y in ds):
            continue
        med = median(d for d, _ in ds)
        unc = max(u + abs(d - med) for d, u in ds)
        if abs(med) <= unc:
            med = 0.0
        adj[a].append((b, -med, unc))   # o_b = o_a - d
        adj[b].append((a, med, unc))
    al = Align()
    if not adj:
        return al
    ref = max(sorted(adj), key=lambda s: len(adj[s]))
    al.off[ref], al.unc[ref] = 0.0, SENTINEL_UNC
    queue = [ref]
    while queue:
        a = queue.pop(0)
        for b, delta, unc in sorted(adj[a]):
            if b not in al.off:
                al.off[b] = al.off[a] + delta   # delta = o_b - o_a
                al.unc[b] = al.unc[a] + unc
                queue.append(b)
    return al


def clock(r, al):
    if r.tcol and r.src in al.off:
        return r.t - al.off[r.src], al.unc[r.src]
    return r.t, UNALIGNED_UNC


# ---------------------------------------------------------------------- claims
class Claim:
    def __init__(self, text):
        self.text = text
        self.type = 'other'
        self.kind = self.ref = None
        self.hedged = False
        self.t = None
        self.res = 60
        self.multi_time = False
        self.speed = self.zone = None
        self.camera = False
        self.device = None
        self.rel = self.sign = self.tol = None


NUMW = {'a': 1, 'one': 1, 'two': 2, 'three': 3, 'four': 4, 'five': 5, 'six': 6, 'seven': 7, 'eight': 8,
        'nine': 9, 'ten': 10, 'fifteen': 15, 'twenty': 20, 'thirty': 30}
REL_RX = re.compile(r'\b(\d+|a|one|two|three|four|five|six|seven|eight|nine|ten|fifteen|twenty|thirty)\s+'
                    r'(second|sec|minute|min|hour)s?\s+(after|before|later than|following|prior to)\s+(.*)', re.I)


def split_sentences(text):
    units, buf = [], ''
    for line in text.splitlines():
        line = line.strip()
        if not line:
            if buf:
                units.append(buf)
            buf = ''
            continue
        buf = (buf + ' ' + line) if buf else line
        if buf[-1] in '.!?"\'':
            units.append(buf)
            buf = ''
    if buf:
        units.append(buf)
    out = []
    for u in units:
        out += [s.strip() for s in re.split(r'(?<=[.!?])\s+(?=[A-Z0-9"\'(\[])', u) if s.strip()]
    return out


def clause_time(c, text, ctx):
    ms = list(TIME_RX.finditer(text))
    if not ms or not ctx.date:
        return
    keys = set()
    for m in ms:
        h = int(m.group(1))
        if m.group(4):
            h = h % 12 + (12 if m.group(4).lower() == 'p' else 0)
        keys.add((h, int(m.group(2)), int(m.group(3) or 0), bool(m.group(3))))
    if len(keys) > 1:
        c.multi_time = True
    h, mi, s, has_s = sorted(keys)[0]
    c.t = epoch_of(ctx.date, h, mi, s, ctx.local)
    c.res = 1 if has_s else 60


def build_claim(clause, sentence, ctx):
    c = Claim(clause)
    c.hedged = bool(HEDGE_RX.search(clause)) or bool(HEDGE_RX.search(sentence) and not TIME_RX.search(clause))
    c.camera = bool(CAMERA_RX.search(sentence))
    dm = re.search(r'\bCAM-\w+', sentence)
    c.device = dm.group(0) if dm else None
    m = REL_RX.search(clause)
    sp = extract_speeds(clause)
    if m:
        unit = {'s': 1, 'm': 60, 'h': 3600}[m.group(2)[0].lower()]
        n = NUMW.get(m.group(1).lower()) or int(m.group(1))
        c.type, c.rel = 'relative', n * unit
        c.sign = -1 if m.group(3).lower() in ('before', 'prior to') else 1
        c.kind, c.ref = kind_of(clause[:m.start()]), kind_of(m.group(4))
        c.tol = max(60.0, 0.5 * c.rel) if c.hedged else max(30.0, 0.1 * c.rel)
        if not (c.kind and c.ref):
            c.type = 'other'
    elif sp:
        c.type = 'speed'
        c.speed, c.zone = sp[0]
        if c.zone is None:
            zm = ZONE_RX.search(clause)
            c.zone = int(zm.group(1) or zm.group(2)) if zm else None
        clause_time(c, sentence if TIME_RX.search(sentence) else clause, ctx)
    elif TIME_RX.search(clause):
        clause_time(c, clause, ctx)
        c.kind = kind_of(clause)
        c.type = 'time' if c.kind else 'other'
    return c


def extract_claims(report, ctx):
    claims = []
    for s in split_sentences(report):
        if re.match(r'^(?:SYNTHETIC\b|Incident\s+\d{4}-\d{2}-\d{2})', s):
            continue
        clauses = [s]
        if TIME_RX.search(s) and extract_speeds(s) and ', ' in s:
            a, b = s.split(', ', 1)
            if (TIME_RX.search(a) and extract_speeds(b) and not extract_speeds(a)) or \
               (extract_speeds(a) and TIME_RX.search(b) and not TIME_RX.search(a)):
                clauses = [a, b]
        claims += [build_claim(c, s, ctx) for c in clauses]
    return claims


# --------------------------------------------------------------------- verdicts
def interval(t, res, hedge):
    return (t - hedge, t + res + hedge)


def overlaps(a, b):
    return a[0] < b[1] and b[0] < a[1]


def status(r, ci, al):
    t, unc = clock(r, al)
    ri = interval(t, r.res, r.hedge)
    if overlaps(ri, ci):
        return 'consistent', 0.0
    g = max(ci[0] - ri[1], ri[0] - ci[1])
    return ('inconsistent' if g > unc else 'ambiguous'), g


def pick_key(x):
    g, r = x
    return (not r.tcol, g, r.file, r.n)


def verdict_time(c, idx, al):
    if c.t is None or c.multi_time:
        return 'not_settled', None
    h = HEDGE_S if c.hedged else 0.0
    ci = interval(c.t, c.res, h)
    buckets = {'s': defaultdict(list), 'w': defaultdict(list)}
    for r, s in idx.get(c.kind, []):
        if r.t is not None:
            st, g = status(r, ci, al)
            buckets[s][st].append((g, r))
    cs, ins, amb = buckets['s']['consistent'], buckets['s']['inconsistent'], buckets['s']['ambiguous']
    cw = buckets['w']['consistent']
    if cs and not ins:
        return 'match', min(cs, key=pick_key)[1]
    if not cs and not amb and not cw and len(ins) == 1:   # one unambiguous event of this kind, far outside any clock error
        return 'conflict', ins[0][1]
    if not cs and not ins and len({r.src for _, r in cw}) >= 2:
        return 'match', min(cw, key=pick_key)[1]
    return 'not_settled', None


def verdict_speed(c, rows, al):
    tol = 3.0 if c.hedged else 1.0
    if c.camera:   # a camera has no vehicle id: only usable when the report itself points at the camera
        if c.t is None:
            return 'not_settled', None
        ci = interval(c.t, c.res, HEDGE_S if c.hedged else 0.0)
        seen, cand = set(), []
        for r in rows:
            if r.is_camera and r.t is not None and (not c.device or r.device == c.device):
                k = (r.src, r.t, r.speed)
                if k not in seen:
                    seen.add(k)
                    cand.append(r)
        over = [r for r in cand if overlaps(interval(clock(r, al)[0], 1, 0.0), ci)]
        if len(over) == 1 and abs(over[0].speed - c.speed) <= tol:
            return 'match', over[0]
        return 'not_settled', None
    cons, inc = [], []
    for r in rows:
        if r.is_camera or not r.speeds or AMBIG_RX.search(r.text or ''):
            continue
        for sp, z in r.speeds:
            if z is not None and c.zone is not None and z != c.zone:
                continue
            if abs(sp - c.speed) <= tol:
                cons.append((r, sp))
            elif z is not None and c.zone is not None:   # contradiction only counts when it names the same zone
                inc.append((r, sp))
    if cons and not inc:
        return 'match', cons[0][0]
    if inc and not cons and len({sp for _, sp in inc}) == 1:
        return 'conflict', inc[0][0]
    return 'not_settled', None


def verdict_rel(c, idx, al):
    subj = [r for r, _ in idx.get(c.kind, []) if r.tcol and r.t is not None]
    ref = [r for r, _ in idx.get(c.ref, []) if r.tcol and r.t is not None]
    lo, hi = c.rel - c.tol, c.rel + c.tol
    res = []
    for a in subj:
        for b in ref:
            same = a.src == b.src
            if a is b or not (same or (a.src in al.off and b.src in al.off)):
                continue   # durations across unaligned clocks are meaningless
            ta, ua = clock(a, al)
            tb, ub = clock(b, al)
            unc = 0.0 if same else ua + ub
            dlo, dhi = ta - (tb + b.res), (ta + a.res) - tb
            if c.sign < 0:
                dlo, dhi = -dhi, -dlo
            if dlo >= lo and dhi <= hi:
                res.append(('c', a))
            elif dhi + unc < lo or dlo - unc > hi:
                res.append(('i', a))
            else:
                res.append(('a', a))
    if any(s == 'c' for s, _ in res) and not any(s == 'i' for s, _ in res):
        return 'match', next(r for s, r in res if s == 'c')   # imprecise pairs only widen, they do not contradict
    if len(res) == 1 and res[0][0] == 'i':
        return 'conflict', res[0][1]
    return 'not_settled', None


def decide(c, rows, idx, al):
    if c.type == 'time':
        return verdict_time(c, idx, al)
    if c.type == 'speed':
        return verdict_speed(c, rows, al)
    if c.type == 'relative':
        return verdict_rel(c, idx, al)
    return 'not_checkable', None


def verify_quote(row, quote, texts):
    """Rule 1: exact substring of the row's raw text (and present verbatim in the source file)."""
    return bool(quote) and quote in row.raw and quote in texts.get(row.file, '')


def finalize(claim, finding, row, texts):
    if finding in ('match', 'conflict'):
        if row is None or not verify_quote(row, row.quote, texts):
            finding = 'not_settled'
        else:
            return {'claim': claim.text, 'finding': finding,
                    'cite': {'file': row.file, 'row': row.n}, 'quote': row.quote}
    return {'claim': claim.text, 'finding': finding}


def run(report_path, rec_dir):
    with open(report_path, 'rb') as f:
        report = decode(f.read())
    rows, texts, ctx = load_all(rec_dir, report)
    al = estimate_offsets(rows)
    idx = defaultdict(list)
    for r in rows:
        for k, s in r.kinds.items():
            idx[k].append((r, s))
    out = []
    for c in extract_claims(report, ctx):
        finding, row = decide(c, rows, idx, al)
        out.append(finalize(c, finding, row, texts))
    return {'findings': out}


def main(argv):
    if len(argv) != 3:
        print('usage: plearun_cli.py REPORT RECORDS_DIR', file=sys.stderr)
        return 2
    if not os.path.isfile(argv[1]) or not os.path.isdir(argv[2]):
        print('REPORT must be a file and RECORDS_DIR a directory', file=sys.stderr)
        return 2
    json.dump(run(argv[1], argv[2]), sys.stdout, indent=2)
    sys.stdout.write('\n')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
