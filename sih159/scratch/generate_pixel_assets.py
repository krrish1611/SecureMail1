from PIL import Image, ImageDraw, ImageFont
import numpy as np

# 1. Load original pixel_mail.png
orig = Image.open('OneDrive/Desktop/sih159/frontend/public/pixel_mail.png').convert('RGBA')
arr = np.array(orig)
w, h = orig.size

# -------------------------------------------------------------
# Asset 1: pixel_mail_back.png (For 360-degree 3D rotation)
# -------------------------------------------------------------
# Back of envelope has the same outer silhouette, stepped black border,
# white fill, and black drop shadow.
# Inside: Clean retro address lines and a forensic seal in the center.

back_img = orig.copy()
b_arr = np.array(back_img)

# Clear inner fold lines (inside the border: x in [50, 630], y in [50, 430])
# Keep the black outer border (approx 40px margin around)
# Let's find inner area:
inner_mask = np.zeros((h, w), dtype=bool)
# Inner rectangle is roughly x: 45 to 635, y: 45 to 435
inner_mask[45:435, 45:635] = True

# Fill inner area with pure white (and keep the right/bottom inner grey shadow)
b_arr[inner_mask & (b_arr[:, :, 3] > 0)] = [253, 253, 253, 255]

# Add inner grey shadow on right edge and bottom edge of inner area
b_arr[410:435, 45:635] = [182, 182, 182, 255] # bottom inner shadow
b_arr[45:435, 610:635] = [182, 182, 182, 255] # right inner shadow

back_clean = Image.fromarray(b_arr)
draw_back = ImageDraw.Draw(back_clean)

# Add retro pixel address lines in dark slate (#1e293b)
line_color = (30, 41, 59, 255)
# Stamp in top right
draw_back.rectangle([540, 65, 615, 140], fill=(74, 144, 226, 255), outline=(6, 6, 6, 255), width=8)

# Center / Left address lines (chunky pixel bars)
draw_back.rectangle([100, 190, 320, 206], fill=line_color)
draw_back.rectangle([100, 230, 480, 246], fill=line_color)
draw_back.rectangle([100, 270, 420, 286], fill=line_color)
draw_back.rectangle([100, 310, 350, 326], fill=line_color)

# PQC Forensic Watermark at bottom
draw_back.rectangle([100, 360, 260, 372], fill=(148, 163, 184, 255))

back_clean.save('OneDrive/Desktop/sih159/frontend/public/pixel_mail_back.png')
print("Created pixel_mail_back.png")

# -------------------------------------------------------------
# Asset 2: pixel_mail_letter.png (The emerging document)
# -------------------------------------------------------------
# Dimensions: 560 x 500
# Pixel art letter with stepped black border, white body, blue forensic header,
# pixel security badge, text lines, and action prompt.

lw, lh = 560, 520
letter = Image.new('RGBA', (lw, lh), (0, 0, 0, 0))
ldraw = ImageDraw.Draw(letter)

# Pixel block size = 10px
px = 10

# Outer stepped black border
# Main body rect: x from 2*px to lw - 4*px, y from 2*px to lh - 4*px
bx0, by0 = 20, 20
bx1, by1 = lw - 40, lh - 40

# Draw black drop shadow (thick retro shadow at bottom & right)
ldraw.rectangle([bx0 + 16, by0 + 16, bx1 + 16, by1 + 16], fill=(6, 6, 6, 255))

# Draw black outer border
ldraw.rectangle([bx0, by0, bx1, by1], fill=(6, 6, 6, 255))

# Draw white paper sheet
ldraw.rectangle([bx0 + 14, by0 + 14, bx1 - 14, by1 - 14], fill=(255, 255, 255, 255))

# Right & bottom inner shading (retro grey fold)
ldraw.rectangle([bx1 - 32, by0 + 14, bx1 - 14, by1 - 14], fill=(203, 213, 225, 255))
ldraw.rectangle([bx0 + 14, by1 - 32, bx1 - 14, by1 - 14], fill=(203, 213, 225, 255))

# Header bar: Dark Cyan / Blue (#0284c7)
ldraw.rectangle([bx0 + 24, by0 + 24, bx1 - 42, by0 + 74], fill=(2, 132, 199, 255))
# Inner accent
ldraw.rectangle([bx0 + 32, by0 + 32, bx0 + 64, by0 + 66], fill=(255, 255, 255, 255))

# Security clearance seal badge (blue square matching stamp)
ldraw.rectangle([bx1 - 96, by0 + 88, bx1 - 50, by0 + 134], fill=(59, 130, 246, 255), outline=(6, 6, 6, 255), width=6)

# Text line bars (pixel style)
# Line 1: Title bar
ldraw.rectangle([bx0 + 36, by0 + 96, bx0 + 320, by0 + 114], fill=(15, 23, 42, 255))
# Line 2: Subtitle
ldraw.rectangle([bx0 + 36, by0 + 124, bx0 + 240, by0 + 136], fill=(100, 116, 139, 255))

# Horizontal divider line
ldraw.rectangle([bx0 + 36, by0 + 152, bx1 - 50, by0 + 158], fill=(6, 6, 6, 255))

# Data rows / status items
# Row 1: PQC Status [PASS]
ldraw.rectangle([bx0 + 36, by0 + 176, bx0 + 180, by0 + 192], fill=(30, 41, 59, 255))
ldraw.rectangle([bx0 + 200, by0 + 176, bx1 - 50, by0 + 192], fill=(16, 185, 129, 255)) # Green pass bar

# Row 2: STARTTLS Audit
ldraw.rectangle([bx0 + 36, by0 + 210, bx0 + 220, by0 + 224], fill=(30, 41, 59, 255))
ldraw.rectangle([bx0 + 240, by0 + 210, bx1 - 50, by0 + 224], fill=(59, 130, 246, 255)) # Blue bar

# Row 3: DMARC / SPF Posture
ldraw.rectangle([bx0 + 36, by0 + 242, bx0 + 190, by0 + 256], fill=(30, 41, 59, 255))
ldraw.rectangle([bx0 + 210, by0 + 242, bx1 - 50, by0 + 256], fill=(168, 85, 247, 255)) # Purple bar

# Row 4: Simulated document lines
for y_off in [280, 304, 328, 352, 376]:
    ldraw.rectangle([bx0 + 36, by0 + y_off, bx1 - 50, by0 + y_off + 12], fill=(226, 232, 240, 255))
    ldraw.rectangle([bx0 + 36, by0 + y_off, bx0 + 180 + (y_off * 3 % 160), by0 + y_off + 12], fill=(71, 85, 105, 255))

# Launch Button Box at bottom: Emerald Green [ ENTER CONSOLE > ]
ldraw.rectangle([bx0 + 36, by0 + 410, bx1 - 50, by0 + 448], fill=(16, 185, 129, 255), outline=(6, 6, 6, 255), width=4)
# Button interior bar
ldraw.rectangle([bx0 + 80, by0 + 424, bx1 - 94, by0 + 434], fill=(255, 255, 255, 255))

letter.save('OneDrive/Desktop/sih159/frontend/public/pixel_mail_letter.png')
print("Created pixel_mail_letter.png")

