# Payloads de Job

## CMD

```json
{
  "job_id": "JOB-1",
  "executor": "cmd",
  "command": "whoami"
}
```

## PowerShell

```json
{
  "job_id": "JOB-2",
  "executor": "powershell",
  "command": "Get-Process | Select-Object -First 5"
}
```

## Python

```json
{
  "job_id": "JOB-3",
  "executor": "python",
  "code": "print('hello from runner')"
}
```

## Atomic Red Team

```json
{
  "job_id": "JOB-4",
  "executor": "atomic",
  "technique_id": "T1059.001",
  "test_number": 1
}
```
