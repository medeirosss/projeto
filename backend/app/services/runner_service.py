from app.repositories.runner_repository import (
    register_runner,
    update_heartbeat,
    get_pending_jobs,
    save_job_result,
)


def register_runner_service(data: dict):
    runner_id = data.get("runner_id")
    if not runner_id:
        raise ValueError("runner_id is required")

    register_runner(
        runner_id=runner_id,
        name=data.get("name"),
        hostname=data.get("hostname"),
    )

    return {
        "success": True,
        "runner_id": runner_id,
        "status": "registered"
    }


def heartbeat_service(data: dict):
    runner_id = data.get("runner_id")
    if not runner_id:
        raise ValueError("runner_id is required")

    update_heartbeat(runner_id)

    return {
        "success": True,
        "runner_id": runner_id,
        "status": "online"
    }


def list_jobs_service(runner_id: str):
    if not runner_id:
        raise ValueError("runner_id is required")

    jobs = get_pending_jobs(runner_id)

    return {
        "success": True,
        "runner_id": runner_id,
        "jobs": jobs
    }


def job_result_service(job_id: int, data: dict):
    runner_id = data.get("runner_id")
    status = data.get("status")

    if not runner_id:
        raise ValueError("runner_id is required")

    if status not in ["success", "failed", "error"]:
        raise ValueError("status must be success, failed or error")

    result = save_job_result(
        job_id=job_id,
        runner_id=runner_id,
        status=status,
        result=data.get("result"),
        error=data.get("error"),
    )

    if not result:
        raise ValueError("job not found or not assigned to this runner")

    return {
        "success": True,
        "job": result
    }