$projectRoot = Split-Path -Parent $PSScriptRoot
$benignJson = Get-Content (Join-Path $projectRoot "configs\sample_benign.json") -Raw

Write-Host "=== 1. Health Endpoint ==="
$h = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -Method Get
Write-Host ("Status        : " + $h.status)
Write-Host ("Model Loaded  : " + $h.model_loaded)
Write-Host ("Feature Count : " + $h.feature_count)

Write-Host ""
Write-Host "=== 2. Real Benign Flow (from sample_benign.json) ==="
$r1 = Invoke-RestMethod -Uri "http://127.0.0.1:8000/predict" -Method Post -Body $benignJson -ContentType "application/json"
Write-Host ("Prediction    : " + $r1.prediction)
Write-Host ("Is DoS        : " + $r1.is_dos)
Write-Host ("Confidence    : " + ($r1.confidence * 100) + "%")
Write-Host ("Latency (ms)  : " + $r1.inference_latency_ms)

Write-Host ""
Write-Host "=== 3. Real High-Volume DoS Attack Flow ==="
$dosBody = '{"Header_Length": 683.5, "Protocol Type": 17.0, "Duration": 64.0, "Rate": 553148.44, "Srate": 553148.44, "Drate": 0.0, "UDP": 1.0, "IPv": 1.0, "LLC": 1.0, "Tot sum": 525.0, "Min": 50.0, "Max": 50.0, "AVG": 50.0, "Tot size": 50.0, "IAT": 101635944.0, "Number": 9.5, "Weight": 141.5}'
$r2 = Invoke-RestMethod -Uri "http://127.0.0.1:8000/predict" -Method Post -Body $dosBody -ContentType "application/json"
Write-Host ("Prediction    : " + $r2.prediction)
Write-Host ("Is DoS        : " + $r2.is_dos)
Write-Host ("Confidence    : " + ($r2.confidence * 100) + "%")
Write-Host ("Latency (ms)  : " + $r2.inference_latency_ms)
