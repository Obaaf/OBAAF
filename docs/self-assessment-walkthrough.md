# Try the self-assessment

The self-assessment is a predefined checklist of 34 questions. It scores answers
you supply and ranks suggested improvements. It does not inspect your accounts,
verify evidence, or use an AI model to generate questions.

Install OBAAF first using the [quick start](../README.md#quick-start). The commands
below work from the OBAAF repository root. The project remains a private draft;
this walkthrough does not grant a licence or authorise distribution.

## Generate and score an answer file

```bash
obaaf assess init --output answers.yaml
```

Open `answers.yaml`. For each item, replace `unanswered` with `yes`, `no`, or `na`
where allowed, and record evidence that another person can check. Keep unknown
answers unanswered. Then run:

```bash
obaaf assess score answers.yaml
```

The output shows the tier reached and a ranked list of open items with fix links.
It is a score of your declarations, not an independent security assessment.

## Generate a browser questionnaire

```bash
obaaf assess form --output assessment.html
```

Open `assessment.html` in a browser. The form runs locally. The questions are the
same predefined checklist as the answer-file version. The repository also ships
an [offline form](../assessment/obaaf-self-assessment.html).

## Reproduce a scoring example

```bash
obaaf assess score examples/self-assessment/tier-one-demo.yaml
```

The [fictional example](../examples/self-assessment/tier-one-demo.yaml) answers all
eight Tier 1 questions yes. Its expected result is **Tier 1 (Accounted)**, with
26 unanswered items across Tiers 2 to 4. No real organisation has been assessed
by that example, and its evidence placeholders are not suitable for real use.

To see why lower tiers matter, copy the example to a new file and change item
`1.1` to `no`. Scoring the copy gives **Tier 0 (Not yet Accounted)**. The tool
requires every item at a tier and below to be satisfied before awarding that tier.

N/A is permitted only on questions with a documented applicability condition.
For example, item `3.6` permits N/A when no AI agents are used; item `1.1` does not.
The scorer rejects N/A for ineligible questions, but cannot independently verify
that an eligible question's applicability condition is absent.

The full [checklist](../spec/self-assessment.md) defines four tiers: Accounted,
Controlled, Verified, and Assured. These names are framework categories, not
certifications. The checklist focuses on game studios and software releases;
review applicability before using it for other project types.
