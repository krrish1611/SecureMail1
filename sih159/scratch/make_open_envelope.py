from PIL import Image, ImageDraw
import numpy as np

# Load original closed envelope
orig = Image.open('OneDrive/Desktop/sih159/frontend/public/pixel_mail.png').convert('RGBA')
arr = np.array(orig)
w, h = orig.size

# The open envelope will have the flap extended upwards!
# Let's make an image with extra height on top: e.g. width = w, height = h + 160
# Base envelope sits at y_offset = 160
flap_h = 160
total_h = h + flap_h
open_img = Image.new('RGBA', (w, total_h), (0, 0, 0, 0))

# Place base envelope (without the closed flap)
# The base envelope is from x=0 to w, y=y_offset to total_h
base_arr = arr.copy()

# The open flap is an upward-pointing triangle:
# Base of flap is from x=45 to x=635 at y = y_offset + 48
# Peak of flap is at x=340, y = 20
draw = ImageDraw.Draw(open_img)

# 1. Back wall of envelope (inside cavity)
# Draw back wall inside the envelope rect (x: 45 to 635, y: flap_h + 45 to flap_h + 435)
cavity_y0 = flap_h + 45
cavity_y1 = flap_h + 435

# First paste the back of the envelope
back_sheet = Image.open('OneDrive/Desktop/sih159/frontend/public/pixel_mail_back.png')
open_img.paste(back_sheet, (0, flap_h))

# Draw the open flap pointing UPWARDS:
# Stepped black border forming the upward triangle:
# Left side from (45, cavity_y0) to (340, 20)
# Right side from (340, 20) to (635, cavity_y0)
flap_poly = [(45, cavity_y0), (340, 25), (635, cavity_y0)]
# Draw black drop shadow for the open flap:
draw.polygon([(45 + 16, cavity_y0), (340 + 16, 25 + 16), (635 + 16, cavity_y0)], fill=(6, 6, 6, 255))
# Draw black border for flap:
draw.polygon(flap_poly, fill=(6, 6, 6, 255))
# Draw white fill inside flap:
draw.polygon([(65, cavity_y0 - 4), (340, 48), (615, cavity_y0 - 4)], fill=(253, 253, 253, 255))
# Shading on right side of flap:
draw.polygon([(340, 48), (615, cavity_y0 - 4), (600, cavity_y0 - 4)], fill=(203, 213, 225, 255))

# Dark interior pocket cavity:
draw.rectangle([65, cavity_y0, 615, cavity_y1 - 20], fill=(226, 232, 240, 255))

# Draw front V-pocket (lower half):
# The lower V pocket has top edge: (45, cavity_y0 + 120) -> (340, cavity_y1 - 60) -> (635, cavity_y0 + 120)
pocket_poly = [
    (45, cavity_y0 + 120),
    (340, cavity_y1 - 60),
    (635, cavity_y0 + 120),
    (635, cavity_y1),
    (45, cavity_y1)
]
# Draw front pocket black border:
draw.polygon(pocket_poly, fill=(6, 6, 6, 255))
# Draw white face of front pocket:
draw.polygon([
    (58, cavity_y0 + 130),
    (340, cavity_y1 - 72),
    (622, cavity_y0 + 130),
    (622, cavity_y1 - 14),
    (58, cavity_y1 - 14)
], fill=(253, 253, 253, 255))

# Front pocket crease lines:
draw.line([(58, cavity_y1 - 14), (340, cavity_y1 - 72)], fill=(6, 6, 6, 255), width=8)
draw.line([(622, cavity_y1 - 14), (340, cavity_y1 - 72)], fill=(6, 6, 6, 255), width=8)

# Add blue stamp on front pocket:
draw.rectangle([540, cavity_y1 - 160, 605, cavity_y1 - 95], fill=(74, 144, 226, 255), outline=(6, 6, 6, 255), width=8)

# Crop/scale to match original 734 width:
open_img.save('OneDrive/Desktop/sih159/frontend/public/pixel_mail_open.png')
print("Created pixel_mail_open.png")
