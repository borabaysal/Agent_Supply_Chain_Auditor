# Repository assets

## `social-preview.png`: GitHub social preview / link card

The image GitHub shows when the repo is linked on LinkedIn, X, Slack and other sites (1280×640, under GitHub's 1 MB limit). It's set in **Settings → General → Social preview**; this copy is kept so it can be edited and re-rendered.

- **Source:** `social-preview.html`, plain HTML/CSS with an inline SVG shield. No external fonts, images or scripts.
- **Safe area:** LinkedIn's small comment thumbnail shows only the centre (about 850×640). Keep the shield, "asca" and the chips within it.

### Re-render

Headless Chrome on macOS:

```bash
cd docs/assets
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless --hide-scrollbars \
  --window-size=1280,640 --screenshot="$PWD/social-preview.png" "file://$PWD/social-preview.html"
```

On Linux, use `chromium --headless …` with the same flags.

**Fonts:** the published image was rendered with DejaVu Sans, the fallback for the CSS font stack on Linux. On a Mac the same HTML renders with San Francisco, which is slightly wider, so check that the six chips still fit on one line before uploading.

### After changing it

1. Upload the new PNG under **Settings → General → Social preview**.
2. Paste the repo URL into https://www.linkedin.com/post-inspector/ to refresh LinkedIn's cached card.
3. Re-post any comment whose card should change. Existing posts and comments keep their old card.
