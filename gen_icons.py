"""Generate Android launcher icons from assets/image.png."""
from PIL import Image, ImageDraw
import os, shutil

SRC = "assets/image.png"
BASE = "app/src/main/res"

DENSITIES = {
    "mipmap-mdpi":    48,
    "mipmap-hdpi":    72,
    "mipmap-xhdpi":   96,
    "mipmap-xxhdpi":  144,
    "mipmap-xxxhdpi": 192,
}

img = Image.open(SRC)
min_dim = min(img.size)
left = (img.width - min_dim) // 2
top = (img.height - min_dim) // 2
img = img.crop((left, top, left + min_dim, top + min_dim))
master = img.resize((1024, 1024), Image.LANCZOS)


def circular_mask(size):
    mask = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(mask)
    draw.ellipse((0, 0, size, size), fill=255)
    return mask


for folder, size in DENSITIES.items():
    os.makedirs(os.path.join(BASE, folder), exist_ok=True)

    icon = master.resize((size, size), Image.LANCZOS)
    path = os.path.join(BASE, folder, "ic_launcher.png")
    icon.save(path, "PNG")
    print(f"  {path}")

    round_icon = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    round_icon.paste(icon, mask=circular_mask(size))
    path_r = os.path.join(BASE, folder, "ic_launcher_round.png")
    round_icon.save(path_r, "PNG")
    print(f"  {path_r}")

logo = master.resize((512, 512), Image.LANCZOS)
logo.save(os.path.join(BASE, "drawable", "ic_hydra_logo.png"), "PNG")
print(f"  drawable/ic_hydra_logo.png")

shutil.copy2(SRC, "app/src/main/assets/image.png")
print(f"  app/src/main/assets/image.png")

print("Done!")
