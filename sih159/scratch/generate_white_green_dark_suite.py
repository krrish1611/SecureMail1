import os
from PIL import Image, ImageDraw
import numpy as np

# 1. Texture Pattern
tex_raw = Image.open('/Users/gauravchauhan/.gemini/antigravity-ide/brain/88152a1b-37cb-41bb-aab9-7e21a6b460bd/.user_uploaded/media_1789238138928.png').convert('RGB')
tw, th = tex_raw.size
tex_cropped = tex_raw.crop((12, 22, tw - 12, th - 12))

def create_white_green_texture(target_w, target_h):
    resized = tex_cropped.resize((target_w, target_h), Image.Resampling.LANCZOS)
    arr = np.array(resized)
    gray = np.mean(arr, axis=2)
    
    out = np.zeros((target_h, target_w, 4), dtype=np.uint8)
    
    # White & Green Mecha Texture:
    # Main Body: Pure Pearl White (#ffffff)
    # Shaded Panels: High-Tech Mint/Pale Green (#dcfce7 / #e6f9ed)
    # Grooves/Chamfers: Light Sage (#bbf7d0)
    # Circuit Lines: Crisp Cyber Emerald Green (#16a34a)
    # Accent Notches/Nodes: Bright Neon Cyber Green (#22c55e)
    for y in range(target_h):
        for x in range(target_w):
            g = gray[y, x]
            if g <= 40: # Tech circuit lines
                out[y, x] = [22, 163, 74, 255] # Vivid Cyber Emerald (#16a34a)
            elif g <= 95: # Accent notches & circuit nodes
                out[y, x] = [34, 197, 94, 255] # Bright Neon Green (#22c55e)
            elif g <= 180: # Groove / chamfer bevel
                out[y, x] = [187, 247, 208, 255] # Pale Sage (#bbf7d0)
            elif g <= 235: # Shaded tech armor panel
                out[y, x] = [228, 251, 235, 255] # Soft Mint Armor Plate
            else: # Main body
                out[y, x] = [255, 255, 255, 255] # Pure White
                
    return out

# -------------------------------------------------------------
# Asset 1: Front Mail (734 x 529)
# -------------------------------------------------------------
base_front = Image.open('frontend/public/pixel_mail.png')
bf_arr = np.array(base_front)
w_f, h_f = base_front.size

is_body_front = (bf_arr[:, :, 3] > 0) & (bf_arr[:, :, 0] > 100)
# Exclude stamp
is_stamp_front = (bf_arr[:, :, 3] > 0) & (bf_arr[:, :, 2] > 150) & (bf_arr[:, :, 0] < 100)
is_body_front = is_body_front & ~is_stamp_front

tex_f = create_white_green_texture(w_f, h_f)
front_out = bf_arr.copy()
front_out[is_body_front] = tex_f[is_body_front]

# Stamp: Clean Emerald Green with NO blue remnant
front_out[77:154, 560:633] = [34, 197, 94, 255] # Solid green fill
# Re-draw stamp black outline
f_img = Image.fromarray(front_out)
f_draw = ImageDraw.Draw(f_img)
f_draw.rectangle([560, 77, 632, 153], outline=(6, 6, 6, 255), width=8)

for path in ['frontend/public/pixel_mail_dark.png', 'frontend/src/assets/pixel_mail_dark.png']:
    f_img.save(path)
    print('Saved', path)

# -------------------------------------------------------------
# Asset 2: Back Mail (734 x 529)
# -------------------------------------------------------------
base_back = Image.open('frontend/public/pixel_mail_back.png')
bb_arr = np.array(base_back)

is_body_back = (bb_arr[:, :, 3] > 0) & (bb_arr[:, :, 0] > 100)
is_stamp_back = (bb_arr[:, :, 3] > 0) & (bb_arr[:, :, 2] > 150) & (bb_arr[:, :, 0] < 100)
is_body_back = is_body_back & ~is_stamp_back

tex_b = create_white_green_texture(w_f, h_f)
back_out = bb_arr.copy()
back_out[is_body_back] = tex_b[is_body_back]

# Stamp in top right
back_out[65:140, 540:615] = [34, 197, 94, 255]

b_img = Image.fromarray(back_out)
b_draw = ImageDraw.Draw(b_img)
# Stamp border
b_draw.rectangle([540, 65, 615, 140], outline=(6, 6, 6, 255), width=8)

# Address lines in vivid cyber emerald green (NO blue!)
line_green = (22, 163, 74, 255)
b_draw.rectangle([100, 190, 320, 206], fill=line_green)
b_draw.rectangle([100, 230, 480, 246], fill=line_green)
b_draw.rectangle([100, 270, 420, 286], fill=line_green)
b_draw.rectangle([100, 310, 350, 326], fill=line_green)
# Watermark in neon lime green
b_draw.rectangle([100, 360, 260, 372], fill=(34, 197, 94, 255))

for path in ['frontend/public/pixel_mail_back_dark.png', 'frontend/src/assets/pixel_mail_back_dark.png']:
    b_img.save(path)
    print('Saved', path)

# -------------------------------------------------------------
# Asset 3: Open Back (734 x 689)
# -------------------------------------------------------------
base_ob = Image.open('frontend/public/pixel_mail_open_back.png')
bob_arr = np.array(base_ob)
w_ob, h_ob = base_ob.size

tex_tall = create_white_green_texture(w_ob, h_ob)
ob_out = bob_arr.copy()
is_ob_body = (bob_arr[:, :, 3] > 0) & (bob_arr[:, :, 0] > 100)
ob_out[is_ob_body] = tex_tall[is_ob_body]

cavity_y0, cavity_y1 = 205, 640
ob_img = Image.fromarray(ob_out)
ob_draw = ImageDraw.Draw(ob_img)
# Clean light mint chamber with emerald grid lines
ob_draw.rectangle([58, cavity_y0, 622, cavity_y1], fill=(240, 253, 244, 255))
for y_c in range(cavity_y0 + 30, cavity_y1, 40):
    ob_draw.line([(58, y_c), (622, y_c)], fill=(187, 247, 208, 255), width=2)

for path in ['frontend/public/pixel_mail_open_back_dark.png', 'frontend/src/assets/pixel_mail_open_back_dark.png']:
    ob_img.save(path)
    print('Saved', path)

# -------------------------------------------------------------
# Asset 4: Pocket Lip (734 x 689)
# -------------------------------------------------------------
base_lip = Image.open('frontend/public/pixel_mail_pocket_lip.png')
blip_arr = np.array(base_lip)

lip_out = blip_arr.copy()
is_lip_body = (blip_arr[:, :, 3] > 0) & (blip_arr[:, :, 0] > 100) & ~((blip_arr[:, :, 2] > 150) & (blip_arr[:, :, 0] < 100))
lip_out[is_lip_body] = tex_tall[is_lip_body]

# Stamp on pocket lip (540, cavity_y1-160) -> 480 to 545, x in 540 to 605
cavity_y1 = 640
lip_out[cavity_y1 - 160:cavity_y1 - 95, 540:605] = [34, 197, 94, 255]

lip_img = Image.fromarray(lip_out)
lip_draw = ImageDraw.Draw(lip_img)
lip_draw.rectangle([540, cavity_y1 - 160, 605, cavity_y1 - 95], outline=(6, 6, 6, 255), width=8)

for path in ['frontend/public/pixel_mail_pocket_lip_dark.png', 'frontend/src/assets/pixel_mail_pocket_lip_dark.png']:
    lip_img.save(path)
    print('Saved', path)

# -------------------------------------------------------------
# Asset 5: Themed Letter for Dark Mode (100% BLUE-FREE, White & Green)
# -------------------------------------------------------------
lw, lh = 560, 520
letter = Image.new('RGBA', (lw, lh), (0, 0, 0, 0))
ldraw = ImageDraw.Draw(letter)

bx0, by0 = 20, 20
bx1, by1 = lw - 40, lh - 40

# Drop shadow
ldraw.rectangle([bx0 + 16, by0 + 16, bx1 + 16, by1 + 16], fill=(0, 0, 0, 240))
# Outer border
ldraw.rectangle([bx0, by0, bx1, by1], fill=(6, 6, 6, 255))
# Paper sheet: Crisp White
ldraw.rectangle([bx0 + 12, by0 + 12, bx1 - 12, by1 - 12], fill=(255, 255, 255, 255))
# Inner bevel: Soft Mint
ldraw.rectangle([bx1 - 28, by0 + 12, bx1 - 12, by1 - 12], fill=(220, 252, 231, 255))
ldraw.rectangle([bx0 + 12, by1 - 28, bx1 - 12, by1 - 12], fill=(220, 252, 231, 255))

# Top Header: Vivid Emerald Green (#16a34a)
ldraw.rectangle([bx0 + 24, by0 + 24, bx1 - 42, by0 + 74], fill=(22, 163, 74, 255))
ldraw.rectangle([bx0 + 32, by0 + 32, bx0 + 64, by0 + 66], fill=(255, 255, 255, 255))

# Security Stamp / Seal (top right): Neon Green (#22c55e) with dark border (NO BLUE!)
ldraw.rectangle([bx1 - 96, by0 + 88, bx1 - 50, by0 + 134], fill=(34, 197, 94, 255), outline=(6, 6, 6, 255), width=5)

# Title & Subtitle
ldraw.rectangle([bx0 + 36, by0 + 96, bx0 + 320, by0 + 114], fill=(15, 23, 42, 255))
ldraw.rectangle([bx0 + 36, by0 + 124, bx0 + 240, by0 + 136], fill=(71, 85, 105, 255))

# Divider: Emerald Green
ldraw.rectangle([bx0 + 36, by0 + 152, bx1 - 50, by0 + 158], fill=(22, 163, 74, 255))

# Data Rows: All Green tones (NO BLUE!)
# Row 1: Emerald Green
ldraw.rectangle([bx0 + 36, by0 + 176, bx0 + 180, by0 + 192], fill=(15, 23, 42, 255))
ldraw.rectangle([bx0 + 200, by0 + 176, bx1 - 50, by0 + 192], fill=(22, 163, 74, 255))

# Row 2: Neon Lime Green (was blue before!)
ldraw.rectangle([bx0 + 36, by0 + 210, bx0 + 220, by0 + 224], fill=(15, 23, 42, 255))
ldraw.rectangle([bx0 + 240, by0 + 210, bx1 - 50, by0 + 224], fill=(34, 197, 94, 255))

# Row 3: Mint Green
ldraw.rectangle([bx0 + 36, by0 + 242, bx0 + 190, by0 + 256], fill=(15, 23, 42, 255))
ldraw.rectangle([bx0 + 210, by0 + 242, bx1 - 50, by0 + 256], fill=(52, 211, 153, 255))

# Simulated lines
for y_off in [280, 304, 328, 352, 376]:
    ldraw.rectangle([bx0 + 36, by0 + y_off, bx1 - 50, by0 + y_off + 12], fill=(228, 251, 235, 255))
    ldraw.rectangle([bx0 + 36, by0 + y_off, bx0 + 180 + (y_off * 3 % 160), by0 + y_off + 12], fill=(71, 85, 105, 255))

# Bottom action bar: Vivid Emerald Green
ldraw.rectangle([bx0 + 36, by0 + 410, bx1 - 50, by0 + 448], fill=(22, 163, 74, 255))
ldraw.rectangle([bx0 + 80, by0 + 424, bx1 - 94, by0 + 434], fill=(255, 255, 255, 255))

for path in ['frontend/public/pixel_mail_letter_dark.png', 'frontend/src/assets/pixel_mail_letter_dark.png']:
    letter.save(path)
    print('Saved', path)

print("White & Green Dark Mode Suite completed with ZERO blue!")
