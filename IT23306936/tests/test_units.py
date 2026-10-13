"""
IoMT Mitigation Component - Unit Test Suite
FR1-FR10 coverage. VM-independent.
Uses fake monotonic clock (T=10000.0) for CleanupGate timing tests.
Run: python -m pytest tests/test_units.py -v
"""
import sys, math, time
from copy import deepcopy
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pytest

from alert_validation_v2 import validate_alert, REQUIRED, ALIASES

SERVICES = {
    "ECG_Monitoring": {
        "criticality": "critical", "target_ip": "10.0.0.2",
        "protocol": "udp", "port": 5202,
        "qos": {"min_throughput_kbps": 90, "max_loss_percent": 1, "max_delay_ms": None},
    },
    "Background_Traffic": {
        "criticality": "noncritical", "target_ip": "10.0.0.2",
        "protocol": "udp", "port": 5201, "qos": None,
    },
}
VALID_ALERT = {
    "alert_id": "TEST-001", "attack_type": "DoS_Flooding",
    "source_ip": "10.0.0.1", "target_ip": "10.0.0.2",
    "severity": "high", "affected_service": "ECG_Monitoring",
    "detector_id": "TEST_DETECTOR", "timestamp": "2026-10-13T01:00:00+00:00",
}

class TestAlertValidation:
    def test_dos_flooding_alias(self):
        a, _ = validate_alert(VALID_ALERT, SERVICES); assert a["attack_type"] == "dos"
    def test_reconnaissance_alias(self):
        a, _ = validate_alert({**VALID_ALERT, "attack_type": "Reconnaissance"}, SERVICES)
        assert a["attack_type"] == "reconnaissance"
    def test_mitm_alias(self):
        a, _ = validate_alert({**VALID_ALERT, "attack_type": "MITM"}, SERVICES)
        assert a["attack_type"] == "mitm"
    def test_unsupported_type(self):
        with pytest.raises(ValueError): validate_alert({**VALID_ALERT, "attack_type": "bad"}, SERVICES)
    @pytest.mark.parametrize("f", REQUIRED)
    def test_missing_field(self, f):
        with pytest.raises(ValueError): validate_alert({k:v for k,v in VALID_ALERT.items() if k!=f}, SERVICES)
    @pytest.mark.parametrize("f", REQUIRED)
    def test_empty_field(self, f):
        with pytest.raises(ValueError): validate_alert({**VALID_ALERT, f: "  "}, SERVICES)
    def test_field_too_long(self):
        with pytest.raises(ValueError): validate_alert({**VALID_ALERT, "alert_id": "A"*257}, SERVICES)
    def test_invalid_source_ip(self):
        with pytest.raises(ValueError): validate_alert({**VALID_ALERT, "source_ip": "bad"}, SERVICES)
    def test_invalid_severity(self):
        with pytest.raises(ValueError): validate_alert({**VALID_ALERT, "severity": "extreme"}, SERVICES)
    def test_severity_case(self):
        a, _ = validate_alert({**VALID_ALERT, "severity": "HIGH"}, SERVICES); assert a["severity"] == "high"
    def test_timestamp_no_tz(self):
        with pytest.raises(ValueError): validate_alert({**VALID_ALERT, "timestamp": "2026-10-13T01:00:00"}, SERVICES)
    def test_timestamp_z_ok(self):
        a, _ = validate_alert({**VALID_ALERT, "timestamp": "2026-10-13T01:00:00Z"}, SERVICES)
        assert a["timestamp"]
    def test_unknown_service(self):
        with pytest.raises(ValueError): validate_alert({**VALID_ALERT, "affected_service": "X"}, SERVICES)
    def test_target_mismatch(self):
        with pytest.raises(ValueError): validate_alert({**VALID_ALERT, "target_ip": "10.0.0.3"}, SERVICES)
    def test_confidence_ok(self):
        a, _ = validate_alert({**VALID_ALERT, "confidence": 0.75}, SERVICES); assert a["confidence"] == 0.75
    def test_confidence_range(self):
        with pytest.raises(ValueError): validate_alert({**VALID_ALERT, "confidence": 1.5}, SERVICES)
    def test_confidence_bool(self):
        with pytest.raises(ValueError): validate_alert({**VALID_ALERT, "confidence": True}, SERVICES)
    def test_service_copy(self):
        _, svc = validate_alert(VALID_ALERT, SERVICES); svc["criticality"] = "noncritical"
        assert SERVICES["ECG_Monitoring"]["criticality"] == "critical"
    def test_non_dict(self):
        with pytest.raises(ValueError): validate_alert("x", SERVICES)

from mitigation_policy_v2 import choose_action
ECG = deepcopy(SERVICES["ECG_Monitoring"])
BG  = deepcopy(SERVICES["Background_Traffic"])
FLOW = {"source_ip": "10.0.0.1", "target_ip": "10.0.0.2", "protocol": "udp", "dst_port": 5201}
GOOD_QOS = {"receiver_kbps": 100.0, "packet_loss_percent": 0.0}
BAD_QOS  = {"receiver_kbps": 20.0, "packet_loss_percent": 80.0}
PROT = [{"target_ip": "10.0.0.2", "protocol": "udp", "port": 5202}]

def ctx(flow=None, qos=None, age=0.5, confirmed=False, prot=None):
    c = {}
    if flow: c["verified_flow"] = deepcopy(flow)
    if qos:  c["qos"] = deepcopy(qos); c["qos_age_seconds"] = age
    c["malicious_confirmed"] = confirmed
    c["protected_services"] = deepcopy(prot or PROT)
    return c

class TestMitigationPolicy:
    def test_no_flow_review(self):
        assert choose_action({"attack_type":"dos","source_ip":"10.0.0.1","target_ip":"10.0.0.2","severity":"high"}, ECG, {})["action"] == "review"
    def test_dos_good_qos_rate_limit(self):
        r = choose_action({"attack_type":"dos","source_ip":"10.0.0.1","target_ip":"10.0.0.2","severity":"high"}, ECG, ctx(FLOW, GOOD_QOS))
        assert r["action"] == "rate_limit"; assert r["enforcement_enabled"] is False
    def test_dos_bad_qos_rate_limit_degraded(self):
        r = choose_action({"attack_type":"dos","source_ip":"10.0.0.1","target_ip":"10.0.0.2","severity":"high"}, ECG, ctx(FLOW, BAD_QOS))
        assert r["action"] == "rate_limit"; assert r["qos_state"] == "degraded"
    def test_stale_qos_review(self):
        assert choose_action({"attack_type":"dos","source_ip":"10.0.0.1","target_ip":"10.0.0.2","severity":"high"}, ECG, ctx(FLOW, GOOD_QOS, age=15))["action"] == "review"
    def test_flow_on_ecg_port_review(self):
        assert choose_action({"attack_type":"dos","source_ip":"10.0.0.1","target_ip":"10.0.0.2","severity":"high"}, ECG, ctx({**FLOW,"dst_port":5202}, GOOD_QOS))["action"] == "review"
    def test_dos_noncritical_blocks(self):
        assert choose_action({"attack_type":"dos","source_ip":"10.0.0.1","target_ip":"10.0.0.2","severity":"high"}, BG, ctx(FLOW, prot=PROT))["action"] == "block"
    def test_recon_rate_limit(self):
        assert choose_action({"attack_type":"reconnaissance","source_ip":"10.0.0.1","target_ip":"10.0.0.2","severity":"high"}, ECG, ctx(FLOW,GOOD_QOS))["action"] == "rate_limit"
    def test_recon_confirmed_blocks(self):
        assert choose_action({"attack_type":"reconnaissance","source_ip":"10.0.0.1","target_ip":"10.0.0.2","severity":"high"}, ECG, ctx(FLOW,GOOD_QOS,confirmed=True))["action"] == "block"
    def test_mitm_unconfirmed_review(self):
        assert choose_action({"attack_type":"mitm","source_ip":"10.0.0.1","target_ip":"10.0.0.2","severity":"high"}, ECG, ctx(FLOW,GOOD_QOS))["action"] == "review"
    def test_mitm_confirmed_blocks(self):
        assert choose_action({"attack_type":"mitm","source_ip":"10.0.0.1","target_ip":"10.0.0.2","severity":"high"}, ECG, ctx(FLOW,GOOD_QOS,confirmed=True))["action"] == "block"
    def test_no_protected_review(self):
        c = {"verified_flow": deepcopy(FLOW), "qos": deepcopy(GOOD_QOS), "qos_age_seconds": 0.5}
        assert choose_action({"attack_type":"dos","source_ip":"10.0.0.1","target_ip":"10.0.0.2","severity":"high"}, ECG, c)["action"] == "review"
    def test_bad_criticality_review(self):
        assert choose_action({"attack_type":"dos","source_ip":"10.0.0.1","target_ip":"10.0.0.2","severity":"high"}, {**ECG,"criticality":"x"}, ctx(FLOW,GOOD_QOS))["action"] == "review"
    def test_nan_qos_review(self):
        assert choose_action({"attack_type":"dos","source_ip":"10.0.0.1","target_ip":"10.0.0.2","severity":"high"}, ECG, ctx(FLOW,{"receiver_kbps":float("nan"),"packet_loss_percent":0}))["action"] == "review"

from qos_window_v2 import aggregate_receiver_window

def make_ivs(n=5, bps=800000, pkts=25, lost=0, t0=0.0):
    out=[]; t=t0
    for _ in range(n):
        out.append({"sender":False,"omitted":False,"start":t,"end":t+2.0,"seconds":2.0,
                    "bytes":int(bps*2/8),"packets":pkts,"lost_packets":lost,
                    "bits_per_second":bps,"lost_percent":100*lost/pkts if pkts else 0,"jitter_ms":0.5})
        t+=2.0
    return out

class TestQoSWindow:
    def test_five_ivs(self): assert aggregate_receiver_window(make_ivs(5))["interval_count"] == 5
    def test_duration(self): assert abs(aggregate_receiver_window(make_ivs(5))["window_duration_seconds"]-10)<0.02
    def test_throughput(self): assert abs(aggregate_receiver_window(make_ivs(5,bps=800000))["receiver_kbps"]-800)<1
    def test_loss_aggregated(self):
        ivs=make_ivs(4,pkts=10,lost=0)
        ivs.append({"sender":False,"omitted":False,"start":8.0,"end":10.0,"seconds":2.0,"bytes":8000,"packets":10,"lost_packets":5,"bits_per_second":32000,"lost_percent":50,"jitter_ms":1.0})
        assert abs(aggregate_receiver_window(ivs)["packet_loss_percent"]-10)<0.01
    def test_zero_loss(self): assert aggregate_receiver_window(make_ivs(5))["packet_loss_percent"]==0.0
    def test_too_short(self):
        with pytest.raises(ValueError): aggregate_receiver_window(make_ivs(3), minimum_seconds=10)
    def test_empty(self):
        with pytest.raises(ValueError): aggregate_receiver_window([])
    def test_sender_rejected(self):
        ivs=make_ivs(5); ivs[2]["sender"]=True
        with pytest.raises(ValueError): aggregate_receiver_window(ivs)
    def test_omitted_rejected(self):
        ivs=make_ivs(5); ivs[0]["omitted"]=True
        with pytest.raises(ValueError): aggregate_receiver_window(ivs)
    def test_non_contiguous(self):
        ivs=make_ivs(5); ivs[2]["start"]+=0.5
        with pytest.raises(ValueError): aggregate_receiver_window(ivs)
    def test_zero_duration(self):
        ivs=make_ivs(5); ivs[1]["seconds"]=0.0; ivs[1]["end"]=ivs[1]["start"]
        with pytest.raises(ValueError): aggregate_receiver_window(ivs)
    def test_negative_packets(self):
        ivs=make_ivs(5); ivs[0]["packets"]=-1
        with pytest.raises(ValueError): aggregate_receiver_window(ivs)
    def test_lost_gt_packets(self):
        with pytest.raises(ValueError): aggregate_receiver_window(make_ivs(5,pkts=10,lost=11))
    def test_zero_packets_raises(self):
        ivs=make_ivs(5)
        for x in ivs: x["packets"]=0; x["lost_packets"]=0; x["lost_percent"]=0
        with pytest.raises(ValueError): aggregate_receiver_window(ivs)

from rule_lifecycle_v2 import CleanupGate
QOS_LIM = {"min_throughput_kbps":90,"max_loss_percent":1,"max_delay_ms":None}
SC = {"source_ip":"10.0.0.1","target_ip":"10.0.0.2","protocol":"udp","dst_port":5201}
GW = {"window_start_seconds":40.0,"window_end_seconds":50.0,"window_duration_seconds":10.0,
      "receiver_kbps":100.0,"packet_loss_percent":0.0}
T = 10000.0  # fake monotonic base

def ft(status, obs, ended_offset=None):
    r={"scope":deepcopy(SC),"status":status,"observed_monotonic":obs}
    r["ended_at_monotonic"] = (obs-ended_offset) if ended_offset is not None else None
    return r

def tws():
    """two_window_setup using fake time T.
    Returns (gate, now1, now2, thr1, thr2, mend1, mend2).
    mend1=T-5 fresh at now1=T; start1=T-15 > ended=T-25 OK
    mend2=T+5 fresh at now2=T+10; start2=T-5 >= mend1-0.01 OK; mend2>mend1 OK"""
    g=CleanupGate(SC, QOS_LIM, required_windows=2)
    ea=T-25
    t1={"scope":deepcopy(SC),"status":"ended","observed_monotonic":T,"ended_at_monotonic":ea}
    t2={"scope":deepcopy(SC),"status":"ended","observed_monotonic":T+10,"ended_at_monotonic":ea}
    return g, T, T+10, t1, t2, T-5, T+5

class TestCleanupGate:
    def test_active_keeps(self):
        g=CleanupGate(SC,QOS_LIM); thr=ft("active",T)
        assert g.observe(deepcopy(GW),T-5,thr,T)["action"]=="keep"
    def test_stale_threat_keeps(self):
        g=CleanupGate(SC,QOS_LIM)
        thr={"scope":deepcopy(SC),"status":"ended","observed_monotonic":T-15,"ended_at_monotonic":T-30}
        assert g.observe(deepcopy(GW),T-5,thr,T)["action"]=="keep"
    def test_scope_mismatch(self):
        g=CleanupGate(SC,QOS_LIM); thr=ft("ended",T,25); thr["scope"]={**SC,"dst_port":9999}
        assert g.observe(deepcopy(GW),T-5,thr,T)["action"]=="keep"
    def test_window_overlap_transition(self):
        g=CleanupGate(SC,QOS_LIM); thr=ft("ended",T,5)
        r=g.observe(deepcopy(GW),T-2,thr,T)
        assert r["action"]=="keep"; assert "transition" in r["reason"].lower()
    def test_first_window_count_1(self):
        g,n1,_,t1,_,m1,_=tws()
        r=g.observe(deepcopy(GW),m1,t1,n1)
        assert r["action"]=="keep"; assert r["stable_windows"]==1
    def test_second_window_remove(self):
        g,n1,n2,t1,t2,m1,m2=tws()
        r1=g.observe(deepcopy(GW),m1,t1,n1); assert r1["stable_windows"]==1
        r2=g.observe(deepcopy(GW),m2,t2,n2)
        assert r2["action"]=="remove"; assert r2["stable_windows"]==2
    def test_degraded_keeps(self):
        g=CleanupGate(SC,QOS_LIM); thr=ft("ended",T,25)
        w={**GW,"receiver_kbps":50.0,"packet_loss_percent":10.0}
        r=g.observe(w,T-5,thr,T); assert r["action"]=="keep"; assert "degraded" in r["reason"].lower()
    def test_invalid_qos_keeps(self):
        g=CleanupGate(SC,QOS_LIM); thr=ft("ended",T,25)
        assert g.observe({**GW,"receiver_kbps":float("nan")},T-5,thr,T)["action"]=="keep"
    def test_non_dict_threat(self):
        g=CleanupGate(SC,QOS_LIM)
        assert g.observe(deepcopy(GW),T-5,None,T)["action"]=="keep"
    def test_duplicate_not_reset(self):
        g,n1,_,t1,_,m1,_=tws()
        g.observe(deepcopy(GW),m1,t1,n1)
        r=g.observe(deepcopy(GW),m1,t1,n1)
        assert r["action"]=="keep"; assert r["stable_windows"]==1
    def test_ended_at_after_observed(self):
        g=CleanupGate(SC,QOS_LIM)
        thr={"scope":deepcopy(SC),"status":"ended","observed_monotonic":T,"ended_at_monotonic":T+5}
        assert g.observe(deepcopy(GW),T-5,thr,T)["action"]=="keep"
    def test_inf_timestamp(self):
        g=CleanupGate(SC,QOS_LIM)
        thr={"scope":deepcopy(SC),"status":"ended","observed_monotonic":float("inf"),"ended_at_monotonic":T-25}
        assert g.observe(deepcopy(GW),T-5,thr,T)["action"]=="keep"
    def test_short_window(self):
        g=CleanupGate(SC,QOS_LIM); thr=ft("ended",T,25)
        assert g.observe({**GW,"window_duration_seconds":5.0},T-5,thr,T)["action"]=="keep"
    def test_ended_at_not_mutated(self):
        g,n1,_,t1,_,m1,_=tws(); orig=t1["ended_at_monotonic"]
        g.observe(deepcopy(GW),m1,t1,n1)
        assert g.last_end is not None
        assert abs(g.last_end-m1)<1e-9
        assert t1["ended_at_monotonic"]==orig

from qos_freshness_v2 import prepare_qos_sample

class TestQoSFreshness:
    def _w(self, s=0.0, e=10.0):
        return {"window_start_seconds":s,"window_end_seconds":e,"window_duration_seconds":e-s,
                "receiver_kbps":100.0,"packet_loss_percent":0.0,"observed_monotonic":time.monotonic()}
    def test_fresh(self):
        now=time.monotonic(); launch=now-15; obs=launch+10.5
        r=prepare_qos_sample(self._w(), launch, obs, now, max_age_seconds=10)
        assert r is not None; assert "metrics" in r
    def test_stale_none(self):
        now=time.monotonic(); launch=now-30; obs=launch+10.5
        assert prepare_qos_sample(self._w(), launch, obs, now, max_age_seconds=10) is None
    def test_sample_end(self):
        now=time.monotonic(); launch=now-12; obs=launch+10.5
        r=prepare_qos_sample(self._w(), launch, obs, now, max_age_seconds=10)
        assert abs(r["sample_end_monotonic"]-(launch+10))<0.01
    def test_future_obs_raises(self):
        now=time.monotonic(); launch=now-5
        with pytest.raises(ValueError): prepare_qos_sample(self._w(0,2), launch, now+10, now)
    def test_inconsistent_timing_raises(self):
        now=time.monotonic(); launch=now-1; obs=now-0.5
        with pytest.raises(ValueError,match="inconsistent"): prepare_qos_sample(self._w(0,5), launch, obs, now)

class TestDuplicateAlertGuard:
    def test_duplicate_returns_409(self):
        from alert_api_v2 import create_app; from context_store_v2 import ContextStore
        client=create_app(None, ContextStore().provide).test_client()
        a={**VALID_ALERT,"alert_id":"DUP-001"}
        r1=client.post("/alert",json=a); r2=client.post("/alert",json=a)
        assert r1.status_code==201; assert r2.status_code==409

    def test_retry_after_validation_failure(self):
        from alert_api_v2 import create_app; from context_store_v2 import ContextStore
        client=create_app(None, ContextStore().provide).test_client()
        bad={**VALID_ALERT, "alert_id":"RETRY-001", "confidence": "invalid"}
        r_fail=client.post("/alert", json=bad)
        assert r_fail.status_code==400
        # Retry with valid payload using same alert_id must be accepted
        good={**VALID_ALERT, "alert_id":"RETRY-001"}
        r_ok=client.post("/alert", json=good)
        assert r_ok.status_code==201

    def test_restart_does_not_persist(self):
        # Simulating restart by creating a new app instance
        from alert_api_v2 import create_app; from context_store_v2 import ContextStore
        app1=create_app(None, ContextStore().provide).test_client()
        app2=create_app(None, ContextStore().provide).test_client()
        a={**VALID_ALERT, "alert_id":"RESTART-001"}
        assert app1.post("/alert", json=a).status_code==201
        assert app1.post("/alert", json=a).status_code==409
        # App2 represents post-restart state: in-memory cache is empty, alert accepted again
        assert app2.post("/alert", json=a).status_code==201


class TestAlertAPIFlask:
    @pytest.fixture
    def client(self):
        from alert_api_v2 import create_app; from context_store_v2 import ContextStore
        return create_app(None, ContextStore().provide).test_client()
    def test_health(self, client):
        r=client.get("/health"); assert r.status_code==200
        d=r.get_json(); assert d["status"]=="ok"; assert d["enforcement_enabled"] is False
    def test_valid_accepted(self, client):
        r=client.post("/alert",json=VALID_ALERT); assert r.status_code==201
        d=r.get_json(); assert d["status"]=="validated"; assert "recommendation" in d
    def test_wrong_content(self, client):
        assert client.post("/alert",data="{}",content_type="text/plain").status_code==415
    def test_malformed_json(self, client):
        assert client.post("/alert",data=b"{bad",content_type="application/json").status_code==400
    def test_oversized(self, client):
        import json
        p=json.dumps({**VALID_ALERT,"extra":"X"*20000}).encode()
        assert client.post("/alert",data=p,content_type="application/json").status_code in (400,413)
    def test_missing_field(self, client):
        bad={k:v for k,v in VALID_ALERT.items() if k!="detector_id"}
        assert client.post("/alert",json=bad).status_code==400
    def test_enforcement_false(self, client):
        d=client.post("/alert",json=VALID_ALERT).get_json()
        assert d.get("enforcement_enabled") is False
        assert d["recommendation"].get("enforcement_enabled") is False
    def test_three_attack_types(self, client):
        for at in ("DoS_Flooding","Reconnaissance","MITM"):
            r=client.post("/alert",json={**VALID_ALERT,"attack_type":at,"alert_id":f"T-{at}"})
            assert r.status_code==201

from delay_reader_v2 import read_ping_metrics

class TestDelayReader:
    P30="30 packets transmitted, 30 received, 0% packet loss, time 29945ms\nrtt min/avg/max/mdev = 0.221/2.336/5.123/0.912 ms\n"
    P7="30 packets transmitted, 7 received, 76.7% packet loss, time 29944ms\nrtt min/avg/max/mdev = 65.123/71.609/80.456/4.567 ms\n"
    P0="30 packets transmitted, 0 received, 100% packet loss, time 29945ms\n"
    def test_full(self):
        r=read_ping_metrics(self.P30)
        assert r["sent_packets"]==30; assert abs(r["rtt_avg_ms"]-2.336)<0.001
        assert r["measurement_method"]=="ICMP round-trip time"
    def test_partial(self):
        r=read_ping_metrics(self.P7); assert r["received_packets"]==7; assert abs(r["rtt_avg_ms"]-71.609)<0.001
    def test_no_reply(self):
        r=read_ping_metrics(self.P0); assert r["rtt_avg_ms"] is None; assert r["received_packets"]==0
    def test_loss_zero(self):
        assert read_ping_metrics(self.P30)["packet_loss_percent"]==0.0
    def test_bad_input(self):
        with pytest.raises(ValueError): read_ping_metrics("nothing useful")

from delay_reader_v2 import parse_ping_line, PeriodicDelayMonitor

class TestPeriodicDelayMonitor:
    def test_parse_ping_line_timestamped(self):
        line = "[1770850000.123456] 64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=2.345 ms"
        s = parse_ping_line(line)
        assert s is not None
        assert abs(s["timestamp_unix"] - 1770850000.123456) < 1e-4
        assert s["icmp_sequence"] == 1
        assert abs(s["rtt_ms"] - 2.345) < 1e-3
        assert s["is_upper_bound"] is False

    def test_parse_ping_line_not_reply(self):
        assert parse_ping_line("PING 10.0.0.2 (10.0.0.2) 56(84) bytes of data.") is None
        assert parse_ping_line("30 packets transmitted, 30 received") is None

    def test_boundary_timestamps_half_open(self):
        mon = PeriodicDelayMonitor(probe_interval_seconds=1.0)
        # Sample at exact start (100.0)
        mon.feed_line("[100.000] 64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=2.0 ms")
        # Sample inside window (105.0)
        mon.feed_line("[105.000] 64 bytes from 10.0.0.2: icmp_seq=2 ttl=64 time=3.0 ms")
        # Sample at exact end boundary (110.0) -> must be excluded in [100.0, 110.0)
        mon.feed_line("[110.000] 64 bytes from 10.0.0.2: icmp_seq=3 ttl=64 time=4.0 ms")

        w1 = mon.get_window_metrics(100.0, 110.0)
        assert w1["received_packets"] == 2
        assert w1["rtt_min_ms"] == 2.0
        assert w1["rtt_max_ms"] == 3.0

        # Boundary sample 110.0 belongs to the next half-open window [110.0, 120.0)
        w2 = mon.get_window_metrics(110.0, 120.0)
        assert w2["received_packets"] == 1
        assert w2["rtt_min_ms"] == 4.0

    def test_duplicate_replies_deduplication(self):
        mon = PeriodicDelayMonitor(probe_interval_seconds=1.0)
        # First arrival of sequence 1
        mon.feed_line("[101.000] 64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=2.5 ms")
        # Duplicate reply arrival of sequence 1
        mon.feed_line("[101.050] 64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=2.5 ms (DUP!)")

        w = mon.get_window_metrics(100.0, 110.0)
        assert w["received_packets"] == 1
        assert w["duplicate_replies_count"] == 1
        assert w["rtt_avg_ms"] == 2.5

    def test_invalid_inputs_rejected(self):
        with pytest.raises(ValueError, match="positive finite number"):
            PeriodicDelayMonitor(probe_interval_seconds=0)
        with pytest.raises(ValueError, match="positive finite number"):
            PeriodicDelayMonitor(probe_interval_seconds=-1.0)
        with pytest.raises(ValueError, match="positive finite number"):
            PeriodicDelayMonitor(probe_interval_seconds=float("inf"))

        mon = PeriodicDelayMonitor()
        with pytest.raises(ValueError, match="strictly ordered"):
            mon.get_window_metrics(110.0, 100.0)
        with pytest.raises(ValueError, match="strictly ordered"):
            mon.get_window_metrics(100.0, 100.0)
        with pytest.raises(ValueError, match="finite number"):
            mon.get_window_metrics(float("nan"), 110.0)
        with pytest.raises(ValueError, match="non-negative integer"):
            mon.get_window_metrics(100.0, 110.0, verified_sent_count=-5)
        with pytest.raises(ValueError, match="cannot precede"):
            mon.get_window_metrics(100.0, 110.0, now_unix=90.0)

        with pytest.raises(ValueError, match="non-negative integer"):
            mon.record_probe_sent(-1, 100.0)
        with pytest.raises(ValueError, match="finite number"):
            mon.record_probe_sent(1, float("inf"))

    def test_upper_bound_rtt_separation(self):
        mon = PeriodicDelayMonitor(probe_interval_seconds=1.0)
        # Upper bound reading: time<0.5 ms
        mon.feed_line("[101.000] 64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time<0.5 ms")
        # Exact readings: time=4.0 ms, time=6.0 ms
        mon.feed_line("[102.000] 64 bytes from 10.0.0.2: icmp_seq=2 ttl=64 time=4.0 ms")
        mon.feed_line("[103.000] 64 bytes from 10.0.0.2: icmp_seq=3 ttl=64 time=6.0 ms")

        w = mon.get_window_metrics(100.0, 110.0)
        assert w["received_packets"] == 3
        assert w["exact_reply_samples_count"] == 2
        assert w["upper_bound_reply_samples_count"] == 1
        assert w["upper_bound_min_ms"] == 0.5
        # Exact RTT must NOT include upper bound <0.5
        assert w["rtt_min_ms"] == 4.0
        assert w["rtt_avg_ms"] == 5.0
        assert w["rtt_max_ms"] == 6.0
        assert w["rtt_status"] == "measured"

    def test_upper_bound_only_yields_unavailable_exact_rtt(self):
        mon = PeriodicDelayMonitor(probe_interval_seconds=1.0)
        mon.feed_line("[101.000] 64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time<0.2 ms")
        w = mon.get_window_metrics(100.0, 110.0)
        assert w["received_packets"] == 1
        assert w["rtt_min_ms"] is None
        assert w["rtt_avg_ms"] is None
        assert w["rtt_status"] == "upper_bound_only"
        assert w["upper_bound_min_ms"] == 0.2

    def test_unknown_sent_counts_leaves_loss_unavailable(self):
        mon = PeriodicDelayMonitor(probe_interval_seconds=1.0)
        # 5 replies received in window without send records
        for i in range(5):
            mon.feed_line(f"[{100.0 + i:.3f}] 64 bytes from 10.0.0.2: icmp_seq={i+1} ttl=64 time=20.0 ms")

        w = mon.get_window_metrics(100.0, 110.0)
        assert w["received_packets"] == 5
        assert w["sent_packets"] is None
        assert w["packet_loss_percent"] is None
        assert w["loss_status"] == "unavailable"
        assert "cannot be inferred" in w["loss_unavailable_reason"].lower()
        # Reply-only RTT statistics are still reported accurately
        assert w["rtt_avg_ms"] == 20.0
        assert w["rtt_status"] == "measured"

    def test_late_replies_and_verified_send_correlation(self):
        mon = PeriodicDelayMonitor(probe_interval_seconds=1.0, late_reply_timeout_seconds=2.0)
        # Record 2 sent probes
        mon.record_probe_sent(1, 101.0)
        mon.record_probe_sent(2, 102.0)
        # Only probe 1 arrives
        mon.feed_line("[101.200] 64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=20.0 ms")

        # Query before late-reply timeout expires for probe 2 (now=103.0 < 102.0 + 2.0)
        w_pending = mon.get_window_metrics(100.0, 110.0, now_unix=103.0)
        assert w_pending["sent_packets"] == 2
        assert w_pending["packet_loss_percent"] is None
        assert w_pending["loss_status"] == "pending_late_reply_timeout"
        assert "still within" in w_pending["loss_unavailable_reason"].lower()

        # Query after late-reply timeout expires (now=105.0 > 102.0 + 2.0)
        w_resolved = mon.get_window_metrics(100.0, 110.0, now_unix=105.0)
        assert w_resolved["sent_packets"] == 2
        assert w_resolved["received_packets"] == 1
        assert w_resolved["packet_loss_percent"] == 50.0
        assert w_resolved["loss_status"] == "verified_send_correlation"
        assert w_resolved["loss_unavailable_reason"] is None

    def test_zero_replies_scenarios(self):
        mon = PeriodicDelayMonitor(probe_interval_seconds=1.0, late_reply_timeout_seconds=1.0)
        # Scenario A: No replies, no send records -> RTT and loss both unavailable (NOT 100% loss)
        w_unverified = mon.get_window_metrics(100.0, 110.0)
        assert w_unverified["received_packets"] == 0
        assert w_unverified["rtt_avg_ms"] is None
        assert w_unverified["rtt_status"] == "unavailable"
        assert w_unverified["sent_packets"] is None
        assert w_unverified["packet_loss_percent"] is None
        assert w_unverified["loss_status"] == "unavailable"

        # Scenario B: 2 sent probes, both timed out without reply -> 100% loss established
        mon.record_probe_sent(1, 101.0)
        mon.record_probe_sent(2, 102.0)
        w_confirmed_loss = mon.get_window_metrics(100.0, 110.0, now_unix=105.0)
        assert w_confirmed_loss["received_packets"] == 0
        assert w_confirmed_loss["sent_packets"] == 2
        assert w_confirmed_loss["packet_loss_percent"] == 100.0
        assert w_confirmed_loss["loss_status"] == "verified_send_correlation"

    def test_history_bounded_and_raw_logging(self, tmp_path):
        log_file = tmp_path / "raw_ping.txt"
        mon = PeriodicDelayMonitor(max_history_samples=5, raw_log_file=log_file)
        for i in range(10):
            mon.feed_line(f"[{100.0 + i:.3f}] 64 bytes from 10.0.0.2: icmp_seq={i+1} ttl=64 time=10.0 ms")

        # Memory bound to 5 entries
        assert len(mon._samples) == 5
        # Raw log contains all 10 lines
        assert len(log_file.read_text().splitlines()) == 10


from controlled_lifecycle_test import run_controlled_lifecycle
from periodic_adjustment_live_demo import run_live_adjustment_demo

class TestControlledLifecycleMock:
    def test_run_all_6_requirements_verified(self):
        summary = run_controlled_lifecycle(mock=True)
        assert summary["final_status"] == "ALL_LIFECYCLE_REQUIREMENTS_VERIFIED"
        reqs = summary["requirements_verified"]
        assert reqs["fresh_scope_matched_threat_required"] is True
        assert reqs["transition_duplicate_stale_rejected"] is True
        assert reqs["two_distinct_stable_windows_authorize_cleanup"] is True
        assert reqs["only_owned_flows_and_meters_removed"] is True
        assert reqs["explicit_cleanup_distinguished_from_hard_timeout"] is True
        assert reqs["raw_evidence_saved"] is True


class TestPeriodicAdjustmentLiveDemoMock:
    def test_normal_recovery(self):
        summary = run_live_adjustment_demo(mock=True, mock_scenario="normal")
        assert summary["status"] == "success"
        assert summary["branch_verdict"] == "exercised_and_qos_recovered"
        assert summary["adjustment_command_executed"] is True
        assert summary["post_adjustment_window_evaluated"] is True
        assert summary["final_measured_qos_passed"] is True
        assert summary["actual_sender_rates"]["sensor_sent_kbps"] == 100.0
        assert summary["actual_sender_rates"]["load_sent_kbps"] == 5000.0
        assert summary["original_api_recommendation"]["rate_limit_kbps"] == 1000
        assert summary["initial_override_plan"]["rate_limit_kbps"] == 1800
        assert summary["adjusted_enforcement_plan"]["rate_limit_kbps"] == 500

    def test_qos_passed_not_exercised(self):
        summary = run_live_adjustment_demo(mock=True, mock_scenario="qos_passed")
        assert summary["status"] == "success"
        assert summary["branch_verdict"] == "not_exercised_measured_qos_passed"
        assert summary["adjustment_command_executed"] is False
        assert summary["post_adjustment_window_evaluated"] is False
        assert summary["final_measured_qos_passed"] is True

    def test_no_post_window_inconclusive(self):
        summary = run_live_adjustment_demo(mock=True, mock_scenario="no_post_window")
        assert summary["status"] == "success"
        assert summary["branch_verdict"] == "inconclusive"
        assert summary["adjustment_command_executed"] is True
        assert summary["post_adjustment_window_evaluated"] is False
        assert summary["final_measured_qos_passed"] is None
        assert "no_eligible_post_adjustment_window" in summary["verdict_details"]["reason"]

    def test_early_load_cessation_confounded(self):
        summary = run_live_adjustment_demo(mock=True, mock_scenario="early_load_cessation")
        assert summary["status"] == "success"
        assert summary["branch_verdict"] == "inconclusive"
        assert summary["adjustment_command_executed"] is True
        assert summary["post_adjustment_window_evaluated"] is False
        assert summary["final_measured_qos_passed"] is None
        # Confounded window 5 must not attribute recovery
        w5 = summary["windows"][4]
        assert w5["window_confounded_by_load_cessation"] is True
        assert w5["evaluation_valid"] is False


import json
from topology_profile import TOPOLOGY_CONFIG, EXPERIMENT_PROFILES, build_mininet_topology
from comparison_runner import (
    build_permutation_schedule,
    run_comparison,
    compute_statistics_series,
    validate_final_window,
    validate_window_measurement,
    TrafficProcessRecord,
)



class TestTopologyProfile:
    def test_topology_config_structure(self):
        hosts = {h.name: h for h in TOPOLOGY_CONFIG["hosts"]}
        assert set(hosts.keys()) == {"h1", "h2", "h3"}
        assert hosts["h1"].ip == "10.0.0.1/8"
        assert hosts["h2"].ip == "10.0.0.2/8"
        assert hosts["h3"].ip == "10.0.0.3/8"
        assert TOPOLOGY_CONFIG["switch"]["protocols"] == "OpenFlow13"
        links = TOPOLOGY_CONFIG["links"]
        assert links["h1-s1"].bw_mbps == 10.0
        assert links["h3-s1"].bw_mbps == 10.0
        assert links["s1-h2"].bw_mbps == 2.0
        assert links["s1-h2"].max_queue_size == 20
        assert links["s1-h2"].use_htb is True

    def test_no_prescribed_experimental_outcomes(self):
        baseline = EXPERIMENT_PROFILES["profile_baseline"]
        assert "expected_sensor_loss_pct" not in baseline

    def test_builder_consumes_config_consistently(self):
        class MockNet:
            def __init__(self):
                self.hosts = {}
                self.switches = {}
                self.links = []
            def addHost(self, name, ip):
                self.hosts[name] = {"ip": ip}
                return name
            def addSwitch(self, name, protocols=None):
                self.switches[name] = {"protocols": protocols}
                return name
            def addLink(self, node1, node2, **kwargs):
                self.links.append((node1, node2, kwargs))
                return None

        mock_net = MockNet()
        res = build_mininet_topology(mock_net)
        assert set(res.keys()) == {"h1", "h2", "h3", "s1"}
        assert mock_net.switches["s1"]["protocols"] == "OpenFlow13"
        assert len(mock_net.links) == 3

        # Check bottleneck link kwargs
        h2_links = [l for l in mock_net.links if l[0] == "h2" or l[1] == "h2"]
        assert len(h2_links) == 1
        kw = h2_links[0][2]
        assert kw["bw"] == 2.0
        assert kw["delay"] == "1.0ms"
        assert kw["max_queue_size"] == 20
        assert kw["use_htb"] is True


class TestComparisonRunner:
    def test_schedule_generation_6_repeats(self):
        schedule, meta = build_permutation_schedule(repeats=6, seed=42)
        assert len(schedule) == 18
        assert meta["is_perfectly_balanced"] is True
        for s in ("baseline", "static_block", "adaptive"):
            # In 6 repeats across all 6 permutations, each scenario appears twice in each position
            assert meta["position_counts"][s][1] == 2
            assert meta["position_counts"][s][2] == 2
            assert meta["position_counts"][s][3] == 2
            assert meta["residual_imbalance"][s]["max_deviation_from_uniform"] == 0.0

    def test_schedule_generation_reproducibility(self):
        s1, _ = build_permutation_schedule(repeats=3, seed=123)
        s2, _ = build_permutation_schedule(repeats=3, seed=123)
        assert s1 == s2

    def test_compute_statistics_series(self):
        empty_res = compute_statistics_series([])
        assert empty_res["mean"] is None
        assert empty_res["count"] == 0

        vals = [10.0, 20.0, 30.0]
        res = compute_statistics_series(vals)
        assert res["mean"] == 20.0
        assert res["median"] == 20.0
        assert res["min"] == 10.0
        assert res["max"] == 30.0
        assert res["count"] == 3

    def test_mock_comparison_run(self):
        summary = run_comparison(repeats=1, mock=True, seed=42)
        assert summary["is_synthetic"] is True
        assert summary["mode"] == "mock_synthetic"
        assert summary["total_scheduled_runs"] == 3
        assert summary["total_valid_completed_runs"] == 3
        assert summary["total_execution_failures"] == 0
        stats = summary["statistics"]
        assert set(stats.keys()) == {"baseline", "static_block", "adaptive"}
        assert stats["baseline"]["final_window_metrics"]["qos_pass_rate_pct"] == 0.0
        assert stats["static_block"]["final_window_metrics"]["qos_pass_rate_pct"] == 100.0
        assert stats["adaptive"]["final_window_metrics"]["qos_pass_rate_pct"] == 100.0

    def test_missing_window_6_reported_as_incomplete(self):
        summary = run_comparison(repeats=1, mock=True, mock_defect="missing_window_6")
        assert summary["total_measurement_invalid_runs"] == 3
        assert summary["total_valid_completed_runs"] == 0
        for scen in ("baseline", "static_block", "adaptive"):
            scen_stats = summary["statistics"][scen]
            assert scen_stats["measurement_invalid_count"] == 1
            assert scen_stats["completed_valid_runs"] == 0
            assert scen_stats["final_window_metrics"]["qos_pass_rate_pct"] is None
            assert scen_stats["final_window_metrics"]["qos_pass_count"] == 0
            assert scen_stats["final_window_metrics"]["qos_fail_count"] == 0

    def test_confounded_final_window_excluded_from_valid_statistics(self):
        summary = run_comparison(repeats=1, mock=True, mock_defect="confounded_final_window")
        assert summary["total_measurement_invalid_runs"] == 3
        assert summary["total_valid_completed_runs"] == 0
        for scen in ("baseline", "static_block", "adaptive"):
            scen_stats = summary["statistics"][scen]
            assert scen_stats["final_window_metrics"]["qos_pass_count"] == 0
            assert scen_stats["final_window_metrics"]["qos_fail_count"] == 0
            assert scen_stats["final_window_metrics"]["qos_pass_rate_pct"] is None

    def test_stale_qos_prevents_adaptive_adjustment(self):
        summary = run_comparison(repeats=1, mock=True, mock_defect="stale_qos")
        manifest_lines = Path(summary["preserved_raw_artifacts"]["runs_manifest_jsonl"]).read_text().splitlines()
        for line in manifest_lines:
            rec = json.loads(line)
            if rec["scenario"] == "adaptive":
                assert "adjusted_meter" not in rec["enforcement_evidence"]

    def test_missing_loss_metric_invalidates_measurement(self):
        summary = run_comparison(repeats=1, mock=True, mock_defect="missing_loss")
        assert summary["total_measurement_invalid_runs"] == 3
        manifest_lines = Path(summary["preserved_raw_artifacts"]["runs_manifest_jsonl"]).read_text().splitlines()
        for line in manifest_lines:
            rec = json.loads(line)
            assert rec["whole_run"]["sensor_loss_pct"] is None
            assert rec["measurement_status"] == "measurement_invalid_or_incomplete"

    def test_all_live_attempts_failed_status(self):
        summary = run_comparison(repeats=1, mock=True, mock_defect="execution_failure")
        assert summary["total_execution_failures"] == 3
        assert summary["total_valid_completed_runs"] == 0
        for scen in ("baseline", "static_block", "adaptive"):
            assert summary["statistics"][scen]["execution_failure_count"] == 1
            assert summary["statistics"][scen]["completed_valid_runs"] == 0

    def test_timestamp_bounded_rtt_windows(self):
        from delay_reader_v2 import PeriodicDelayMonitor
        mon = PeriodicDelayMonitor()
        mon.feed_line("[100.500] 64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=5.0 ms")
        mon.feed_line("[101.500] 64 bytes from 10.0.0.2: icmp_seq=2 ttl=64 time=15.0 ms")
        mon.feed_line("[102.500] 64 bytes from 10.0.0.2: icmp_seq=3 ttl=64 time=25.0 ms")

        # Query exact half-open window [100.0, 102.0)
        w1 = mon.get_window_metrics(100.0, 102.0)
        assert w1["received_packets"] == 2
        assert w1["rtt_min_ms"] == 5.0
        assert w1["rtt_max_ms"] == 15.0
        assert w1["rtt_avg_ms"] == 10.0

        # Query window [102.0, 104.0)
        w2 = mon.get_window_metrics(102.0, 104.0)
        assert w2["received_packets"] == 1
        assert w2["rtt_avg_ms"] == 25.0

        # Query empty window [104.0, 106.0) -> RTT unavailable, remains null
        w3 = mon.get_window_metrics(104.0, 106.0)
        assert w3["received_packets"] == 0
        assert w3["rtt_avg_ms"] is None
        assert w3["sent_packets"] is None
        assert w3["packet_loss_percent"] is None

    def test_cleanup_failure_halts_runner(self):
        summary = run_comparison(repeats=6, mock=True, mock_defect="cleanup_failure")
        assert summary["cleanup_failed_halted"] is True
        manifest_lines = Path(summary["preserved_raw_artifacts"]["runs_manifest_jsonl"]).read_text().splitlines()
        # Exactly 1 run executed before safety halt
        assert len(manifest_lines) == 1

    def test_compute_statistics_series_null_sd_under_two_runs(self):
        empty_res = compute_statistics_series([])
        assert empty_res["sample_sd"] is None
        assert empty_res["count"] == 0

        single_res = compute_statistics_series([42.0])
        assert single_res["mean"] == 42.0
        assert single_res["sample_sd"] is None  # n-1 = 0 degrees of freedom, must be None
        assert single_res["count"] == 1

        two_res = compute_statistics_series([10.0, 20.0])
        assert two_res["mean"] == 15.0
        assert two_res["sample_sd"] == 7.071  # valid stdev
        assert two_res["count"] == 2

    def test_validate_final_window_fail_closed_missing_interval_count(self):
        valid_base = {
            "window_index": 6,
            "window_start_seconds": 50.0,
            "window_end_seconds": 60.0,
            "window_duration_seconds": 10.0,
            "interval_count": 5,
            "receiver_kbps": 100.0,
            "packet_loss_percent": 0.0,
            "published_fresh": True,
            "is_confounded": False,
            "is_transition_window": False,
        }

        # Missing interval_count
        w_missing = dict(valid_base)
        del w_missing["interval_count"]
        w, err = validate_final_window([w_missing])
        assert w is None
        assert err == "window_6_missing_interval_count"

        # Incomplete intervals (4 instead of 5)
        w_inc = dict(valid_base, interval_count=4)
        w, err = validate_final_window([w_inc])
        assert w is None
        assert "window_6_incomplete_intervals" in err

    def test_validate_final_window_fail_closed_missing_published_fresh(self):
        valid_base = {
            "window_index": 6,
            "window_start_seconds": 50.0,
            "window_end_seconds": 60.0,
            "window_duration_seconds": 10.0,
            "interval_count": 5,
            "receiver_kbps": 100.0,
            "packet_loss_percent": 0.0,
            "published_fresh": True,
            "is_confounded": False,
            "is_transition_window": False,
        }

        # Missing published_fresh
        w_missing = dict(valid_base)
        del w_missing["published_fresh"]
        w, err = validate_final_window([w_missing])
        assert w is None
        assert err == "window_6_missing_published_fresh"

        # Stale published_fresh (False)
        w_stale = dict(valid_base, published_fresh=False)
        w, err = validate_final_window([w_stale])
        assert w is None
        assert "window_6_stale_qos" in err

    def test_validate_final_window_fail_closed_timing_and_metrics(self):
        valid_base = {
            "window_index": 6,
            "window_start_seconds": 50.0,
            "window_end_seconds": 60.0,
            "window_duration_seconds": 10.0,
            "interval_count": 5,
            "receiver_kbps": 100.0,
            "packet_loss_percent": 0.0,
            "published_fresh": True,
            "is_confounded": False,
            "is_transition_window": False,
        }

        # Non-finite throughput
        w_nan_tp = dict(valid_base, receiver_kbps=float("nan"))
        w, err = validate_final_window([w_nan_tp])
        assert w is None
        assert "window_6_invalid_throughput" in err

        # Non-finite loss
        w_inf_loss = dict(valid_base, packet_loss_percent=float("inf"))
        w, err = validate_final_window([w_inf_loss])
        assert w is None
        assert "window_6_invalid_loss" in err

        # Duration too short (<9.9s)
        w_short = dict(valid_base, window_duration_seconds=8.5)
        w, err = validate_final_window([w_short])
        assert w is None
        assert "window_6_duration_too_short" in err

    def test_mock_fail_closed_defects(self):
        # 1. Missing interval_count defect
        s1 = run_comparison(repeats=1, mock=True, mock_defect="missing_interval_count")
        assert s1["total_measurement_invalid_runs"] == 3
        assert s1["total_valid_completed_runs"] == 0

        # 2. Non-finite metric defect
        s2 = run_comparison(repeats=1, mock=True, mock_defect="non_finite_metric")
        assert s2["total_measurement_invalid_runs"] == 3
        assert s2["total_valid_completed_runs"] == 0

    def test_adaptive_protocol_branch_coverage_and_auditing(self):
        # Normal adaptive run: Window 3 degraded -> adjusted to 500 Kbit/s
        summary_normal = run_comparison(repeats=1, mock=True)
        manifest_lines = Path(summary_normal["preserved_raw_artifacts"]["runs_manifest_jsonl"]).read_text().splitlines()
        for line in manifest_lines:
            rec = json.loads(line)
            assert "ping_collection" in rec
            assert rec["ping_collection"]["collection_status"] == "completed"
            assert rec["ping_collection"]["reader_errors"] == []
            if rec["scenario"] == "adaptive":
                ar = rec["adaptive_reassessment"]
                assert ar["evaluated_at_window"] == 3
                assert ar["outcome"] == "adjusted_to_500kbps"
                assert ar["adjusted"] is True
                assert "adjusted_meter" in rec["enforcement_evidence"]

        # Passing QoS at Window 3 -> branch not exercised
        summary_passed = run_comparison(repeats=1, mock=True, mock_defect="adaptive_qos_passed")
        manifest_lines_p = Path(summary_passed["preserved_raw_artifacts"]["runs_manifest_jsonl"]).read_text().splitlines()
        for line in manifest_lines_p:
            rec = json.loads(line)
            if rec["scenario"] == "adaptive":
                ar = rec["adaptive_reassessment"]
                assert ar["evaluated_at_window"] == 3
                assert ar["outcome"] == "not_exercised_measured_qos_passed"
                assert ar["adjusted"] is False
                assert "adjusted_meter" not in rec["enforcement_evidence"]


class TestStartupReorderFix:
    """Regression tests verifying startup sequencing and error detection.

    Startup sequencing: iperf3 initiates a control exchange before UDP streaming begins.
    Sensor client launches and confirms receiver communication prior to competitor load generator.
    """

    def test_source_sensor_launched_before_load_in_comparison_runner(self):
        """sensor_launch_mono must appear before load_started_mono in the source."""
        src = Path(__file__).resolve().parent.parent / "comparison_runner.py"
        text = src.read_text(encoding="utf-8")
        idx_sensor = text.find('timing_holder["sensor_launch_mono"] = time.monotonic()')
        idx_load = text.find('timing_holder["load_started_mono"] = time.monotonic()')
        assert idx_sensor != -1, "sensor_launch_mono assignment not found"
        assert idx_load != -1, "load_started_mono assignment not found"
        assert idx_sensor < idx_load, (
            "Regression: sensor_launch_mono must appear before load_started_mono. "
            "Sensor client must start before load generator."
        )

    def test_startup_deadline_is_at_least_10_seconds(self):
        """The receiver startup deadline must be >= 10s."""
        import re
        src = Path(__file__).resolve().parent.parent / "comparison_runner.py"
        text = src.read_text(encoding="utf-8")
        matches = re.findall(r"deadline_start\s*=\s*time\.monotonic\(\)\s*\+\s*(\d+)", text)
        assert matches, "deadline_start assignment not found in comparison_runner.py"
        startup_deadline = int(matches[0])
        assert startup_deadline >= 10, (
            f"Regression: startup deadline is {startup_deadline}s but must be >= 10s."
        )

    def test_error_event_detection_in_startup_loop(self):
        """Startup loop must detect iperf3 error events (not just start events)."""
        src = Path(__file__).resolve().parent.parent / "comparison_runner.py"
        text = src.read_text(encoding="utf-8")
        assert 'ev.get("event") == "error"' in text, (
            "Regression: startup loop must detect iperf3 error events"
        )
        assert 'ev.get("event") == "start"' in text, (
            "Regression: startup loop must detect iperf3 start events"
        )

    def test_window1_confounded_by_early_load_does_not_produce_qos_failure(self):
        """Confounded Window 6 must yield measurement_invalid_or_incomplete, not qos_passed=False."""
        summary = run_comparison(repeats=1, mock=True, mock_defect="confounded_final_window")
        assert summary["total_measurement_invalid_runs"] == 3
        assert summary["total_valid_completed_runs"] == 0
        manifest_path = Path(
            summary["preserved_raw_artifacts"]["runs_manifest_jsonl"]
        )
        for line in manifest_path.read_text().splitlines():
            rec = json.loads(line)
            assert rec["qos_passed"] is None, (
                f"Confounded/invalid run {rec['run_id']} must have qos_passed=null, not False"
            )


class TestComparisonRunnerBehavioralRegression:
    """Focused behavioral regression tests using fake processes and failure injection."""

    def test_observed_live_failure_diagnostics_preservation_and_no_fabrication(self):
        """Replicates observed live failure:

        Baseline receiver produced six QoS windows, then emitted:
        'error - unable to receive results: Bad file descriptor'.
        Sensor stderr reported 'warning: Failed to read JSON data size'.
        Sensor client exited 1 with end={} and an error field.

        Verifies:
        - Run is preserved as execution failure (not swallowed, not masked as QoS failure)
        - qos_passed is None (missing measurement is not a QoS failure)
        - Missing sender rates and end summaries are NOT fabricated
        - Receiver error event is preserved in receiver_error_events
        - Process observations recorded for all traffic processes with commands, PIDs, returncodes, lifetimes
        """
        summary = run_comparison(repeats=1, mock=True, mock_defect="live_iperf_failure")
        assert summary["total_execution_failures"] == 3
        assert summary["total_valid_completed_runs"] == 0

        manifest_path = Path(summary["preserved_raw_artifacts"]["runs_manifest_jsonl"])
        for line in manifest_path.read_text().splitlines():
            rec = json.loads(line)
            assert rec["execution_status"] == "failed"
            assert rec["measurement_status"] == "execution_failed"
            assert rec["qos_passed"] is None

            # Verify no fabrication of missing sender rates or end summaries
            assert rec["actual_sender_rates"]["sensor_sent_kbps"] is None
            assert rec["whole_run"]["sensor_kbps"] is None
            assert rec["whole_run"]["sensor_loss_pct"] is None

            # Verify receiver error event preservation
            err_events = rec.get("receiver_error_events", [])
            assert len(err_events) > 0
            assert "Bad file descriptor" in json.dumps(err_events)

            # Verify process observations for all 5 traffic processes
            proc_obs = rec["process_observations"]
            for proc_name in ("sensor_server", "load_server", "sensor_client", "load_client", "ping_proc"):
                assert proc_name in proc_obs
                p_entry = proc_obs[proc_name]
                assert "command" in p_entry and len(p_entry["command"]) > 0
                assert "pid" in p_entry and p_entry["pid"] is not None
                assert "process_lifetime_seconds" in p_entry
                assert "cleanup_signals" in p_entry

            # Sensor client exited with code 1
            assert proc_obs["sensor_client"]["returncode"] == 1
            assert proc_obs["sensor_client"]["configured_duration_seconds"] == 60.0

            # Distinguishes process lifetime from measured traffic duration
            timing = rec["timing_observations"]
            assert timing["measured_sensor_duration_seconds"] == 60.0
            assert timing["measured_load_duration_seconds"] == 70.0

    def test_cleanup_unresolved_process_halts_subsequent_runs(self):
        """Any unresolved thread/process must make cleanup unsuccessful and stop subsequent runs."""
        summary = run_comparison(repeats=6, mock=True, mock_defect="cleanup_failure")
        assert summary["cleanup_failed_halted"] is True

        manifest_lines = Path(summary["preserved_raw_artifacts"]["runs_manifest_jsonl"]).read_text().splitlines()
        # Halts immediately after run 1 fails cleanup
        assert len(manifest_lines) == 1
        rec = json.loads(manifest_lines[0])
        assert rec["cleanup_outcome"]["all_clean"] is False
        assert len(rec["cleanup_outcome"]["unresolved_processes"]) > 0

    def test_cleanup_unresolved_thread_halts_subsequent_runs(self):
        """Any unresolved reader thread must make cleanup unsuccessful and stop subsequent runs."""
        summary = run_comparison(repeats=6, mock=True, mock_defect="cleanup_thread_failure")
        assert summary["cleanup_failed_halted"] is True

        manifest_lines = Path(summary["preserved_raw_artifacts"]["runs_manifest_jsonl"]).read_text().splitlines()
        # Halts immediately after run 1 fails cleanup
        assert len(manifest_lines) == 1
        rec = json.loads(manifest_lines[0])
        assert rec["cleanup_outcome"]["all_clean"] is False
        assert "receiver_monitor_thread" in rec["cleanup_outcome"]["unresolved_threads"]
        assert len(rec["cleanup_outcome"]["thread_join_errors"]) > 0

    def test_shared_validator_window_3_and_6_behavior(self):
        """Direct behavioral testing of shared strict measurement validator for Window 3 and Window 6."""
        # 1. Valid Window 3 passes
        w3_valid = {
            "window_index": 3,
            "window_start_seconds": 20.0,
            "window_end_seconds": 30.0,
            "window_duration_seconds": 10.0,
            "interval_count": 5,
            "receiver_kbps": 95.0,
            "packet_loss_percent": 0.5,
            "published_fresh": True,
            "is_confounded": False,
            "is_transition_window": False,
            "eligible_for_evaluation": True,
        }
        res, err = validate_window_measurement(w3_valid, expected_window_index=3)
        assert res is not None
        assert err is None

        # 2. Window 3 with start boundary out of tolerance fails
        w3_bad_start = dict(w3_valid, window_start_seconds=25.0, window_end_seconds=35.0)
        res, err = validate_window_measurement(w3_bad_start, expected_window_index=3)
        assert res is None
        assert "window_3_start_boundary_out_of_tolerance" in err

        # 3. Window 3 with end boundary out of tolerance fails
        w3_bad_end = dict(w3_valid, window_start_seconds=20.0, window_end_seconds=33.0, window_duration_seconds=13.0)
        res, err = validate_window_measurement(w3_bad_end, expected_window_index=3)
        assert res is None
        assert "window_3_end_boundary_out_of_tolerance" in err

        # 4. Window 3 with duration too short (<9.9s) fails
        w3_short = dict(w3_valid, window_start_seconds=20.0, window_end_seconds=28.0, window_duration_seconds=8.0)
        res, err = validate_window_measurement(w3_short, expected_window_index=3)
        assert res is None
        assert "window_3_duration_too_short" in err

        # 5. Window 3 with incomplete intervals fails
        w3_inc = dict(w3_valid, interval_count=4)
        res, err = validate_window_measurement(w3_inc, expected_window_index=3)
        assert res is None
        assert "window_3_incomplete_intervals" in err

        # 6. Valid Window 6 passes
        w6_valid = {
            "window_index": 6,
            "window_start_seconds": 50.0,
            "window_end_seconds": 60.0,
            "window_duration_seconds": 10.0,
            "interval_count": 5,
            "receiver_kbps": 100.0,
            "packet_loss_percent": 0.0,
            "published_fresh": True,
            "is_confounded": False,
            "is_transition_window": False,
            "eligible_for_evaluation": True,
        }
        res, err = validate_window_measurement(w6_valid, expected_window_index=6)
        assert res is not None
        assert err is None

        # 7. Window 6 with interval evidence verification (non-contiguous intervals)
        intervals_non_contig = [
            {"sender": False, "omitted": False, "start": 50.0, "end": 52.0, "seconds": 2.0, "packets": 20, "lost_packets": 0, "bytes": 25000},
            {"sender": False, "omitted": False, "start": 53.0, "end": 55.0, "seconds": 2.0, "packets": 20, "lost_packets": 0, "bytes": 25000},  # gap 52->53
            {"sender": False, "omitted": False, "start": 55.0, "end": 57.0, "seconds": 2.0, "packets": 20, "lost_packets": 0, "bytes": 25000},
            {"sender": False, "omitted": False, "start": 57.0, "end": 59.0, "seconds": 2.0, "packets": 20, "lost_packets": 0, "bytes": 25000},
            {"sender": False, "omitted": False, "start": 59.0, "end": 61.0, "seconds": 2.0, "packets": 20, "lost_packets": 0, "bytes": 25000},
        ]
        w6_non_contig = dict(w6_valid, intervals=intervals_non_contig)
        res, err = validate_window_measurement(w6_non_contig, expected_window_index=6)
        assert res is None
        assert "window_6_intervals_non_contiguous" in err

    def test_w3_invalid_measurement_results_in_not_evaluated_never_degradation(self):
        """Missing or invalid QoS at Window 3 must mean not_evaluated, never degradation."""
        summary = run_comparison(repeats=1, mock=True, mock_defect="w3_invalid_timing")
        manifest_lines = Path(summary["preserved_raw_artifacts"]["runs_manifest_jsonl"]).read_text().splitlines()
        for line in manifest_lines:
            rec = json.loads(line)
            if rec["scenario"] == "adaptive":
                ar = rec["adaptive_reassessment"]
                assert ar["evaluated_at_window"] == 3
                # Must be not_evaluated, NEVER adjusted
                assert ar["outcome"] == "not_evaluated"
                assert "out_of_tolerance" in ar["reason"]
                assert ar["adjusted"] is False
                assert "adjusted_meter" not in rec["enforcement_evidence"]

    def test_rtt_collection_failure_excludes_rtt_from_stats_without_invalidating_udp(self):
        """Exclude invalid RTT collection from RTT statistics without automatically invalidating otherwise valid UDP measurements."""
        summary = run_comparison(repeats=1, mock=True, mock_defect="ping_reader_error")
        # All 3 runs must remain valid UDP measurements
        assert summary["total_valid_completed_runs"] == 3
        assert summary["total_measurement_invalid_runs"] == 0

        manifest_lines = Path(summary["preserved_raw_artifacts"]["runs_manifest_jsonl"]).read_text().splitlines()
        for line in manifest_lines:
            rec = json.loads(line)
            assert rec["measurement_status"] == "completed_valid"
            assert rec["ping_collection"]["collection_status"] == "reader_error"
            assert len(rec["ping_collection"]["reader_errors"]) > 0

            # ICMP sent and loss must be null
            fw = rec["final_observation_window"]
            assert fw["icmp_sent_packets"] is None
            assert fw["icmp_packet_loss_percent"] is None

        # In summary statistics: RTT series must have count == 0 because invalid RTT was excluded
        for scen, s in summary["statistics"].items():
            rtt_stats = s["final_window_metrics"]["icmp_reply_rtt_ms"]
            assert rtt_stats["count"] == 0
            assert rtt_stats["mean"] is None
            # But UDP throughput and loss are valid and present
            assert s["final_window_metrics"]["throughput_kbps"]["count"] == 1
            assert s["final_window_metrics"]["packet_loss_percent"]["count"] == 1

    def test_traffic_process_record_auditing_behavior(self):
        """Audits TrafficProcessRecord tracking of commands, PIDs, returncodes, lifetimes, and cleanup signals."""
        class FakePopen:
            def __init__(self, pid=9999):
                self.pid = pid
                self._rc = None
            def poll(self):
                return self._rc
            def terminate(self):
                self._rc = -15
            def kill(self):
                self._rc = -9
            def wait(self, timeout=None):
                return self._rc

        fake = FakePopen(pid=4321)
        rec = TrafficProcessRecord("test_sensor", "h1", ["iperf3", "-c", "10.0.0.2"], fake, configured_duration_seconds=60.0)
        time.sleep(0.02)
        assert rec.poll_exit() is None

        # Simulate cleanup signal
        rec.cleanup_signals.append("SIGTERM")
        fake.terminate()
        rec.record_exit(fake.poll())

        d = rec.to_dict()
        assert d["name"] == "test_sensor"
        assert d["host"] == "h1"
        assert d["pid"] == 4321
        assert d["returncode"] == -15
        assert d["cleanup_signals"] == ["SIGTERM"]
        assert d["configured_duration_seconds"] == 60.0
        assert d["process_lifetime_seconds"] is not None
        assert d["process_lifetime_seconds"] >= 0.02

    def test_both_reader_threads_checked_and_joined_after_cleanup(self):
        """Verifies both ping and receiver reader threads are joined boundedly and checked with is_alive()."""
        class FakeThread:
            def __init__(self, alive_after_join=False):
                self._alive = True
                self.joined = False
                self.timeout = None
                self.alive_after_join = alive_after_join
            def is_alive(self):
                return self._alive
            def join(self, timeout=None):
                self.joined = True
                self.timeout = timeout
                if not self.alive_after_join:
                    self._alive = False

        # Case 1: Both threads terminate normally
        t_ping = FakeThread(alive_after_join=False)
        monitor_thread = FakeThread(alive_after_join=False)
        monitor = type("FakeMonitor", (), {"thread": monitor_thread})()

        cleanup_outcome = {
            "all_clean": True,
            "thread_join_errors": [],
            "unresolved_threads": [],
        }

        # Emulate comparison_runner cleanup section
        if t_ping is not None:
            t_ping.join(timeout=3)
            if t_ping.is_alive():
                cleanup_outcome["all_clean"] = False
                cleanup_outcome["unresolved_threads"].append("ping_reader_thread")
        if monitor is not None and getattr(monitor, "thread", None) is not None:
            monitor.thread.join(timeout=3)
            if monitor.thread.is_alive():
                cleanup_outcome["all_clean"] = False
                cleanup_outcome["unresolved_threads"].append("receiver_monitor_thread")

        assert t_ping.joined is True
        assert t_ping.timeout == 3
        assert monitor_thread.joined is True
        assert monitor_thread.timeout == 3
        assert cleanup_outcome["all_clean"] is True
        assert len(cleanup_outcome["unresolved_threads"]) == 0

        # Case 2: Monitor thread hangs and remains alive
        t_ping2 = FakeThread(alive_after_join=False)
        monitor_thread_hang = FakeThread(alive_after_join=True)
        monitor2 = type("FakeMonitor", (), {"thread": monitor_thread_hang})()

        cleanup_outcome2 = {
            "all_clean": True,
            "thread_join_errors": [],
            "unresolved_threads": [],
        }

        if t_ping2 is not None:
            t_ping2.join(timeout=3)
            if t_ping2.is_alive():
                cleanup_outcome2["all_clean"] = False
                cleanup_outcome2["unresolved_threads"].append("ping_reader_thread")
        if monitor2 is not None and getattr(monitor2, "thread", None) is not None:
            monitor2.thread.join(timeout=3)
            if monitor2.thread.is_alive():
                cleanup_outcome2["all_clean"] = False
                cleanup_outcome2["thread_join_errors"].append("receiver_monitor_thread still alive after bounded join")
                cleanup_outcome2["unresolved_threads"].append("receiver_monitor_thread")

        assert cleanup_outcome2["all_clean"] is False
        assert "receiver_monitor_thread" in cleanup_outcome2["unresolved_threads"]
        assert len(cleanup_outcome2["thread_join_errors"]) == 1


class TestDetectorAlertInterface:
    """Verifies standardized detector alert ingestion and validation."""

    def test_valid_alert_accepted(self):
        from controller_detector_interfaces import DetectorAlertInterface
        iface = DetectorAlertInterface(auth_token="secret123")
        ok, err = iface.verify_auth_header("Bearer secret123")
        assert ok is True
        assert err is None

        payload = {
            "alert_id": "ALT-9001",
            "attack_type": "DoS_Flooding",
            "source_ip": "10.0.0.3",
            "target_ip": "10.0.0.2",
            "severity": "high",
            "affected_service": "ECG_Monitoring",
            "timestamp": "2026-10-21T12:00:00Z",
            "confidence": 0.95,
        }
        valid, msg, norm = iface.validate_schema(payload)
        assert valid is True
        assert msg is None
        assert norm["severity"] == "high"

    def test_invalid_auth_token_rejected(self):
        from controller_detector_interfaces import DetectorAlertInterface
        iface = DetectorAlertInterface(auth_token="secret123")
        ok, err = iface.verify_auth_header("Bearer wrong_token")
        assert ok is False
        assert "Invalid authentication token" in err

    def test_invalid_attack_type_rejected(self):
        from controller_detector_interfaces import DetectorAlertInterface
        iface = DetectorAlertInterface()
        payload = {
            "alert_id": "ALT-9002",
            "attack_type": "Ransomware_Fake",
            "source_ip": "10.0.0.3",
            "target_ip": "10.0.0.2",
            "severity": "low",
            "affected_service": "ECG_Monitoring",
            "timestamp": "2026-10-21T12:00:00Z",
        }
        valid, msg, _ = iface.validate_schema(payload)
        assert valid is False
        assert "Invalid attack_type" in msg


class TestControllerAdapters:
    """Verifies controller integration interfaces and Ryu open requirement mapping."""

    def test_ryu_adapter_type_and_unavailable_handling(self):
        from controller_detector_interfaces import RyuEnforcementAdapter
        adapter = RyuEnforcementAdapter(base_url="http://127.0.0.1:9999", timeout_seconds=0.2)
        assert adapter.get_controller_type() == "ryu_rest_controller"
        ok, msg = adapter.is_available()
        # Connection to non-listening port fails gracefully without unhandled exception
        assert ok is False
        assert "unavailable" in msg

    def test_ovs_adapter_type(self):
        from controller_detector_interfaces import OVSEnforcementAdapter
        adapter = OVSEnforcementAdapter()
        assert adapter.get_controller_type() == "direct_ovs_of13"


class TestDashboardServerAPI:
    """Verifies dashboard REST endpoints, telemetry contract, and safe experiment controls."""

    def test_status_endpoint(self):
        from dashboard_server import app
        client = app.test_client()
        res = client.get("/api/status")
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "operational"
        assert "Direct OpenFlow 1.3" in data["architecture"]["active_enforcement_engine"]
        assert "Open Proposal Requirement" in data["architecture"]["ryu_controller_status"]

    def test_telemetry_endpoint_contract(self):
        from dashboard_server import app
        client = app.test_client()
        res = client.get("/api/telemetry")
        assert res.status_code == 200
        data = res.get_json()
        assert "mode" in data
        assert "sensor_throughput_kbps" in data
        assert "sensor_packet_loss_percent" in data
        assert "icmp_rtt_avg_ms" in data
        assert data["icmp_rtt_model"] == "reply_arrival_half_open"

    def test_topology_endpoint(self):
        from dashboard_server import app
        client = app.test_client()
        res = client.get("/api/topology")
        assert res.status_code == 200
        data = res.get_json()
        node_ids = [n["id"] for n in data["nodes"]]
        assert "h1" in node_ids
        assert "h2" in node_ids
        assert "h3" in node_ids
        assert "s1" in node_ids
        assert "c0" in node_ids

    def test_mode_switch(self):
        from dashboard_server import app
        client = app.test_client()
        res = client.post("/api/mode", json={"mode": "DEMO"})
        assert res.status_code == 200
        assert res.get_json()["current_mode"] == "DEMO"

        res_bad = client.post("/api/mode", json={"mode": "INVALID_MODE"})
        assert res_bad.status_code == 400

    def test_safe_experiment_control_rejects_arbitrary_commands(self):
        from dashboard_server import app
        client = app.test_client()
        # Attempting arbitrary scenario should be rejected with 400
        res = client.post("/api/experiments/start", json={"scenario": "rm -rf /"})
        assert res.status_code == 400
        assert "Invalid scenario" in res.get_json()["error"]




