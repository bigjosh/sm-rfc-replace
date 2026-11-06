# Squishy CASIO logotext ideas

Three playful takes on the CASIO wordmark for a watch made of squishy material.
All letterforms are plain filled paths (no font needed), so they open in
Inkscape / Illustrator / Fusion / any laser or mold-making tool.

| File | Idea |
|---|---|
| `casio-squish-1-thumb-pressed.svg` | The wordmark pressed flat by a thumb: squashed to 62% height, bulging out at the waist and spreading at the base, with a contact shadow. |
| `casio-squish-2-jelly-bounce.svg` | Gummy-candy letters, each a different colour, tumbling on a bouncy baseline and nudging into each other. |
| `casio-squish-3-pillow-puff.svg` | Inflated plush letters with a stitched seam, overlapping like cushions. |

Each SVG has the same layer structure:

- `#outline` - one path per letter (`#C`, `#A`, `#S`, `#I`, `#O`). Use only this group for a single-colour emboss / mold.
- `#shadow`, `#shading`, `#seam` - decorative layers for the colour version. Delete them for fabrication.

`generate.py` regenerates the files from Michroma-Regular.ttf (SIL OFL, the free
Microgramma/Eurostile clone that most closely matches the real logo):

```
pip install fonttools shapely numpy
python3 generate.py Michroma-Regular.ttf .
```

Tweak the numbers at the top of each `opt*()` function (squash ratio, bulge, rotation,
overlap, corner radius) to taste.

Note: CASIO is a registered trademark. These are fine for a personal / one-off project,
not for anything sold.
