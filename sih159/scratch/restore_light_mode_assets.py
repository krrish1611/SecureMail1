"""Restore light mode mail assets to original purple/lavender theme (reverting #cbff00 override)."""
import os
from PIL import Image, ImageDraw
import numpy as np

tex_raw = Image.open('/Users/gauravchauhan/.gemini/antigravity-ide/brain/88152a1b-37cb-41bb-aab9-7e21a6b460bd/.user_uploaded/media_1789238138928.png').convert('RGB')
tw, th = tex_raw.size
tex_cropped = tex_raw.crop((12, 22, tw - 12, th - 12))

def create_light_texture(target_w, target_h):
    """Original Light Futuristic Ceramic Mecha Theme (purple/lavender)."""
    resized = tex_cropped.resize((target_w, target_h), Image.Resampling.LANCZOS)
    arr = np.array(resized)
    gray = np.mean(arr, axis=2)
    
    out = np.zeros((target_h, target_w, 4), dtype=np.uint8)
    
    for y in range(target_h):
        for x in range(target_w):
            g = gray[y, x]
            if g <= 40:  # Circuit line
                out[y, x] = [51, 65, 85, 255]      # Sleek dark slate
            elif g <= 95:  # Accent ticks & nodes
                out[y, x] = [116, 46, 197, 255]     # Royal Purple
            elif g <= 180:  # Chamfer shadow
                out[y, x] = [203, 213, 225, 255]    # Slate groove
            elif g <= 235:  # Shaded panel
                out[y, x] = [238, 233, 250, 255]    # Soft lavender panel
            else:  # Main ceramic body
                out[y, x] = [253, 253, 255, 255]    # Clean pearl white
                    
    return out

# Asset 1: Front Mail (734 x 529) -> pixel_mail_light.png
base_front = Image.open('frontend/public/pixel_mail.png')
bf_arr = np.array(base_front)
w_f, h_f = base_front.size

is_body_front = (bf_arr[:, :, 3] > 0) & (bf_arr[:, :, 0] > 100) & ~((bf_arr[:, :, 2] > 200) & (bf_arr[:, :, 0] < 100))
is_stamp_front = (bf_arr[:, :, 3] > 0) & (bf_arr[:, :, 2] > 200) & (bf_arr[:, :, 0] < 100)

tex_f = create_light_texture(w_f, h_f)
front_out = bf_arr.copy()
front_out[is_body_front] = tex_f[is_body_front]
front_out[is_stamp_front] = [116, 46, 197, 255]  # Royal Purple stamp

f_img = Image.fromarray(front_out)
for path in ['frontend/public/pixel_mail_light.png', 'frontend/src/assets/pixel_mail_light.png']:
    f_img.save(path)
    print('Saved', path)

# Asset 2: Back Mail (734 x 529) -> pixel_mail_back_light.png
base_back = Image.open('frontend/public/pixel_mail_back.png')
bb_arr = np.array(base_back)

is_body_back = (bb_arr[:, :, 3] > 0) & (bb_arr[:, :, 0] > 100) & ~((bb_arr[:, :, 2] > 200) & (bb_arr[:, :, 0] < 100))
is_stamp_back = (bb_arr[:, :, 3] > 0) & (bb_arr[:, :, 2] > 200) & (bb_arr[:, :, 0] < 100)

tex_b = create_light_texture(w_f, h_f)
back_out = bb_arr.copy()
back_out[is_body_back] = tex_b[is_body_back]
back_out[is_stamp_back] = [116, 46, 197, 255]

img_b = Image.fromarray(back_out)
b_draw = ImageDraw.Draw(img_b)
line_color = (116, 46, 197, 255)   # Royal purple address lines
sub_color = (147, 51, 234, 255)    # Violet watermark
b_draw.rectangle([100, 190, 320, 206], fill=line_color)
b_draw.rectangle([100, 230, 480, 246], fill=line_color)
b_draw.rectangle([100, 270, 420, 286], fill=line_color)
b_draw.rectangle([100, 310, 350, 326], fill=line_color)
b_draw.rectangle([100, 360, 260, 372], fill=sub_color)

for path in ['frontend/public/pixel_mail_back_light.png', 'frontend/src/assets/pixel_mail_back_light.png']:
    img_b.save(path)
    print('Saved', path)

# Asset 3: Open Back (734 x 689) -> pixel_mail_open_back_light.png
base_ob = Image.open('frontend/public/pixel_mail_open_back.png')
bob_arr = np.array(base_ob)
w_ob, h_ob = base_ob.size

tex_tall = create_light_texture(w_ob, h_ob)
ob_out = bob_arr.copy()
is_ob_body = (bob_arr[:, :, 3] > 0) & (bob_arr[:, :, 0] > 100)
ob_out[is_ob_body] = tex_tall[is_ob_body]

cavity_y0, cavity_y1 = 205, 640
ob_img = Image.fromarray(ob_out)
ob_draw = ImageDraw.Draw(ob_img)
cavity_fill = (241, 245, 249, 255)
cavity_grid = (218, 224, 233, 255)
ob_draw.rectangle([58, cavity_y0, 622, cavity_y1], fill=cavity_fill)
for y_c in range(cavity_y0 + 30, cavity_y1, 40):
    ob_draw.line([(58, y_c), (622, y_c)], fill=cavity_grid, width=2)

for path in ['frontend/public/pixel_mail_open_back_light.png', 'frontend/src/assets/pixel_mail_open_back_light.png']:
    ob_img.save(path)
    print('Saved', path)

# Asset 4: Pocket Lip (734 x 689) -> pixel_mail_pocket_lip_light.png
base_lip = Image.open('frontend/public/pixel_mail_pocket_lip.png')
blip_arr = np.array(base_lip)

lip_out = blip_arr.copy()
is_lip_body = (blip_arr[:, :, 3] > 0) & (blip_arr[:, :, 0] > 100) & ~((blip_arr[:, :, 2] > 200) & (blip_arr[:, :, 0] < 100))
is_lip_stamp = (blip_arr[:, :, 3] > 0) & (blip_arr[:, :, 2] > 200) & (blip_arr[:, :, 0] < 100)

lip_out[is_lip_body] = tex_tall[is_lip_body]
lip_out[is_lip_stamp] = [116, 46, 197, 255]

lip_img = Image.fromarray(lip_out)
for path in ['frontend/public/pixel_mail_pocket_lip_light.png', 'frontend/src/assets/pixel_mail_pocket_lip_light.png']:
    lip_img.save(path)
    print('Saved', path)

# Asset 5: Themed Letter for Light Mode (Purple/Lavender) -> pixel_mail_letter_light.png
lw, lh = 560, 520
letter = Image.new('RGBA', (lw, lh), (0, 0, 0, 0))
ldraw = ImageDraw.Draw(letter)

bx0, by0 = 20, 20
bx1, by1 = lw - 40, lh - 40

# Drop shadow
ldraw.rectangle([bx0 + 16, by0 + 16, bx1 + 16, by1 + 16], fill=(0, 0, 0, 60))
# Outer border
ldraw.rectangle([bx0, by0, bx1, by1], fill=(51, 65, 85, 255))
# Paper sheet: Crisp White
ldraw.rectangle([bx0 + 12, by0 + 12, bx1 - 12, by1 - 12], fill=(255, 255, 255, 255))
# Inner bevel: Soft Lavender
ldraw.rectangle([bx1 - 28, by0 + 12, bx1 - 12, by1 - 12], fill=(238, 233, 250, 255))
ldraw.rectangle([bx0 + 12, by1 - 28, bx1 - 12, by1 - 12], fill=(238, 233, 250, 255))

# Top Header: Royal Purple
ldraw.rectangle([bx0 + 24, by0 + 24, bx1 - 42, by0 + 74], fill=(116, 46, 197, 255))
ldraw.rectangle([bx0 + 32, by0 + 32, bx0 + 64, by0 + 66], fill=(255, 255, 255, 255))

# Security Stamp / Seal: Violet with dark border
ldraw.rectangle([bx1 - 96, by0 + 88, bx1 - 50, by0 + 134], fill=(147, 51, 234, 255), outline=(51, 65, 85, 255), width=5)

# Title & Subtitle
ldraw.rectangle([bx0 + 36, by0 + 96, bx0 + 320, by0 + 114], fill=(15, 23, 42, 255))
ldraw.rectangle([bx0 + 36, by0 + 124, bx0 + 240, by0 + 136], fill=(71, 85, 105, 255))

# Divider: Royal Purple
ldraw.rectangle([bx0 + 36, by0 + 152, bx1 - 50, by0 + 158], fill=(116, 46, 197, 255))

# Data Rows
ldraw.rectangle([bx0 + 36, by0 + 176, bx0 + 180, by0 + 192], fill=(15, 23, 42, 255))
ldraw.rectangle([bx0 + 200, by0 + 176, bx1 - 50, by0 + 192], fill=(116, 46, 197, 255))

ldraw.rectangle([bx0 + 36, by0 + 210, bx0 + 220, by0 + 224], fill=(15, 23, 42, 255))
ldraw.rectangle([bx0 + 240, by0 + 210, bx1 - 50, by0 + 224], fill=(147, 51, 234, 255))

ldraw.rectangle([bx0 + 36, by0 + 242, bx0 + 190, by0 + 256], fill=(15, 23, 42, 255))
ldraw.rectangle([bx0 + 210, by0 + 242, bx1 - 50, by0 + 256], fill=(192, 132, 252, 255))

# Simulated lines
for y_off in [280, 304, 328, 352, 376]:
    ldraw.rectangle([bx0 + 36, by0 + y_off, bx1 - 50, by0 + y_off + 12], fill=(238, 233, 250, 255))
    ldraw.rectangle([bx0 + 36, by0 + y_off, bx0 + 180 + (y_off * 3 % 160), by0 + y_off + 12], fill=(71, 85, 105, 255))

# Bottom action bar: Royal Purple
ldraw.rectangle([bx0 + 36, by0 + 410, bx1 - 50, by0 + 448], fill=(116, 46, 197, 255))
ldraw.rectangle([bx0 + 80, by0 + 424, bx1 - 94, by0 + 434], fill=(255, 255, 255, 255))

for path in ['frontend/public/pixel_mail_letter_light.png', 'frontend/src/assets/pixel_mail_letter_light.png']:
    letter.save(path)
    print('Saved', path)

print("--- Light mode assets restored to original purple/lavender theme ---")
