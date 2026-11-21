"""Static evidence that output uploaded by an agent job could reach another job."""

from __future__ import annotations

from collections.abc import Iterable

from obaaf.checker.workflow import Job, Workflow, _downloads_from_trigger_run, is_local_reference


def _subscribes(candidate: Workflow, producer: Workflow) -> bool:
    triggers = candidate.triggers
    if "workflow_run" not in triggers:
        return False
    config = triggers["workflow_run"]
    names = config.get("workflows") if isinstance(config, dict) else None
    if isinstance(names, str):
        names = [names]
    name = producer.raw.get("name")
    if not isinstance(name, str) or not name.strip() or "${{" in name:
        return True
    if not isinstance(names, list) or not names:
        return True
    return any(not isinstance(item, str) or not item.strip() or "${{" in item
               or item.casefold() == name.casefold() for item in names)


def _may_upload(step) -> bool:
    """`actions/upload-artifact`, an action named like an artifact upload (`actions/upload-pages-artifact`,
    whose artifact `actions/deploy-pages` or a download by name can take), or a local action the checker
    does not read here. An upload by an action with another name is not followed."""
    action = (step.action or "").lower()
    return (step.is_local or step.uses_action("actions/upload-artifact") or "upload-artifact" in action
            or "upload-pages-artifact" in action or "artifact-upload" in action)


def _might_download_from_any_run(job: Job) -> bool:
    """A job in any workflow of the repository that can bring another run's files into it, whatever starts
    it: the checker's reading of a download from another run (`_downloads_from_trigger_run`: a `run-id` or
    `repository` given to `actions/download-artifact`, dawidd6's action and its forks, `gh run download`,
    the artifacts API), a call of a reusable workflow in another repository, whose jobs are not read, or a
    local action, not read here. A call of a workflow of this repository is read where that workflow is."""
    uses = job.raw.get("uses")
    if uses is not None and not is_local_reference(uses):
        return True
    return any(step.is_local for step in job.steps) or _downloads_from_trigger_run(job)


def _might_download(job: Job) -> bool:
    # A reusable job or local action can do the download inside its implementation.
    # The flat steps of a partially read composite cannot prove absence.
    if "uses" in job.raw or any(step.is_local for step in job.steps):
        return True
    return (any(step.uses_action("actions/download-artifact") for step in job.steps)
            or _downloads_from_trigger_run(job))


def artifact_may_be_consumed(repository: Iterable[Workflow] | None, workflow: Workflow, job: Job) -> bool:
    """Whether repository evidence leaves a possible consumer of this job's artifact.

    Pass None when the full workflow inventory is unavailable. All jobs in
    the workflow qualify regardless of needs, artifact name or conditional steps.
    A workflow_run subscriber may also consume the output, and so may a job in any
    workflow of the repository that can download another run's artifacts (a
    dispatched, scheduled or push workflow can name the producer's run). Stop at an
    opaque reusable-workflow boundary, including a producer that runs as a called workflow.
    """
    if not any(_may_upload(step) for step in job.steps):
        return False
    if repository is None or workflow.error or workflow.problems or workflow.callable:
        return True
    if any(_might_download(other) for other in workflow.jobs.values()):
        return True
    for candidate in repository:
        if candidate.error or candidate.problems:
            return True
        if _subscribes(candidate, workflow) and any(_might_download(other) for other in candidate.jobs.values()):
            return True
        # Review of #357 (run gannet): a workflow that is not started by this one can still download its
        # artifacts by run id, for example dawidd6/action-download-artifact with `workflow: agent.yml` in a
        # dispatched deploy, or actions/download-artifact with `run-id` and `github-token` on a schedule.
        if any(_might_download_from_any_run(other) for other in candidate.jobs.values()):
            return True
    return False
