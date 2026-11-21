"""Static evidence that output uploaded by an agent job could reach another job."""

from __future__ import annotations

from collections.abc import Iterable

from obaaf.checker.workflow import Job, Workflow, _downloads_from_trigger_run


def _subscribes(candidate: Workflow, producer: Workflow) -> bool:
    triggers = candidate.triggers
    if "workflow_run" not in triggers:
        return False
    config = triggers["workflow_run"]
    names = config.get("workflows") if isinstance(config, dict) else None
    if isinstance(names, str):
        names = [names]
    name = producer.raw.get("name")
    if not isinstance(name, str) or not name.strip() or not isinstance(names, list) or not names:
        return True
    return any(not isinstance(item, str) or not item.strip() or "${{" in item
               or item.casefold() == name.casefold() for item in names)


def _might_download(job: Job) -> bool:
    # A reusable job or local action can do the download inside its implementation.
    # The flat steps of a partially read composite cannot prove absence.
    if "uses" in job.raw or any(step.is_local for step in job.steps):
        return True
    return (any(step.uses_action("actions/download-artifact") for step in job.steps)
            or _downloads_from_trigger_run(job))


def artifact_may_be_consumed(repository: Iterable[Workflow] | None, workflow: Workflow, job: Job) -> bool:
    """Whether repository evidence leaves a possible consumer of this job's artifact.

    Pass None when the full workflow inventory is unavailable. All other jobs in
    the workflow qualify regardless of needs, artifact name or conditional steps.
    A workflow_run subscriber may also consume the output. Stop at an opaque
    reusable-workflow boundary, including a producer that runs as a called workflow.
    """
    if not any(step.uses_action("actions/upload-artifact") or step.is_local for step in job.steps):
        return False
    if repository is None or workflow.error or workflow.problems or workflow.callable:
        return True
    if any(_might_download(other) for other in workflow.jobs.values() if other.id != job.id):
        return True
    for candidate in repository:
        if candidate.error or candidate.problems:
            return True
        if _subscribes(candidate, workflow) and any(_might_download(other) for other in candidate.jobs.values()):
            return True
    return False
