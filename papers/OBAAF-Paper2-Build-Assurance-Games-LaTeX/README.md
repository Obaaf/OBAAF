# Securing the Game Build: A Sector Profile of SSDF and SLSA and a Self-Assessment Model for Independent Studios

DOI: [10.5281/zenodo.23622802](https://doi.org/10.5281/zenodo.23622802) (Zenodo).

LaTeX source for submission to ACM Digital Threats: Research and Practice (DTRAP), in ACM's acmart template
(acmsmall, review mode with line numbers). Part of the Open Build and Agent Assurance
Framework (OBAAF).

## Files

- `main.tex`: the whole paper in one file
- `refs.bib`: 58 references (BibTeX, ACM-Reference-Format)
- `figures/`: vector PDF figures, with their SVG sources

## Build

- **Overleaf:** New Project > Upload Project > choose this zip > Recompile. The compiler
  should be pdfLaTeX (the default).
- **Local:** `pdflatex main`, `bibtex main`, `pdflatex main`, `pdflatex main`

## Before you submit

1. Get written approval from the author's employer to submit, and to use the affiliation.
2. Replace "Affiliation to be confirmed" in `main.tex`, and check the email address.
3. Check the target venue's submission requirements before submitting.
4. Confirm the CCS concepts at https://dl.acm.org/ccs.
5. Check the journal's current author guidelines for length and abstract limits.
6. For a double-anonymous venue, add the `anonymous` class option and cite the companion
   paper in the third person.

## Other venues

ACM Games: Research and Practice (alternative journal): replace \acmJournal{DTRAP}
with \acmJournal{GAMES}. If your acmart version does not know GAMES, change acmsmall
to manuscript in the class line and delete the \acmJournal line.

Maintain this LaTeX source as the authoritative manuscript and rebuild the PDF after edits.
