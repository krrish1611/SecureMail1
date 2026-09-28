import os
from PIL import Image, ImageDraw, ImageFilter
import numpy as np

# 1. Load and prepare texture pattern
tex_raw = Image.open('/Users/gauravchauhan/.gemini/antigravity-ide/brain/88152a1b-37cb-41bb-aab9-7e21a6b460bd/.user_uploaded/media_1789238138928.png').convert('RGB')
tw, th = tex_raw.size
# Crop away top black header bar and bottom margin to isolate pure circuit panel texture
tex_cropped = tex_raw.crop((12, 22, tw - 12, th - 12))

def create_themed_texture(target_w, target_h, mode='dark'):
    resized = tex_cropped.resize((target_w, target_h), Image.Resampling.LANCZOS)
    arr = np.array(resized)
    gray = np.mean(arr, axis=2)
    
    out = np.zeros((target_h, target_w, 4), dtype=np.uint8)
    
    if mode == 'dark':
        # Dark Cyber Mecha Theme:
        # Base body: #0c1222
        # Shaded panels: #18233c
        # Inner grooves: #070a14
        # Lines: Electric Cyan #38bdf8
        # Accent ticks: Neon Chartreuse #d4ff00
        for y in range(target_h):
            for x in range(target_w):
                g = gray[y, x]
                if g <= 40: # Sharp tech circuit line
                    out[y, x] = [56, 189, 248, 255] # Electric cyan
                elif g <= 95: # Accent ticks & anti-aliased nodes
                    out[y, x] = [212, 255, 0, 255] # Neon chartreuse
                elif g <= 180: # Groove / chamfer shadow
                    out[y, x] = [8, 12, 22, 255] # Deep stealth groove
                elif g <= 235: # Shaded tech armor panel
                    out[y, x] = [26, 38, 64, 255] # Cyber armor plate
                else: # Main body
                    out[y, x] = [14, 21, 38, 255] # Dark cyber slate
    else:
        # Light Futuristic Ceramic Mecha Theme:
        # Base body: Crisp Pearl White #ffffff / #fbfbfe
        # Shaded panels: Soft Lavender Ceramic #ede8f8
        # Inner grooves: Soft slate #cbd5e1
        # Lines: Sleek dark slate #334155
        # Accent ticks: Vivid Royal Purple #742ec5
        for y in range(target_h):
            for x in range(target_w):
                g = gray[y, x]
                if g <= 40: # Circuit line
                    out[y, x] = [51, 65, 85, 255] # Sleek dark slate
                elif g <= 95: # Accent ticks & nodes
                    out[y, x] = [116, 46, 197, 255] # Royal Purple
                elif g <= 180: # Chamfer shadow
                    out[y, x] = [203, 213, 225, 255] # Slate groove
                elif g <= 235: # Shaded panel
                    out[y, x] = [238, 233, 250, 255] # Soft lavender panel
                else: # Main ceramic body
                    out[y, x] = [253, 253, 255, 255] # Clean pearl white
                    
    return out

# Generate Front Mail (734 x 529)
base_front = Image.open('frontend/public/pixel_mail.png')
bf_arr = np.array(base_front)
w_f, h_f = base_front.size

is_body_front = (bf_arr[:, :, 3] > 0) & (bf_arr[:, :, 0] > 100) & ~((bf_arr[:, :, 2] > 200) & (bf_arr[:, :, 0] < 100))
is_stamp_front = (bf_arr[:, :, 3] > 0) & (bf_arr[:, :, 2] > 200) & (bf_arr[:, :, 0] < 100)

for mode in ['dark', 'light']:
    tex_f = create_themed_texture(w_f, h_f, mode=mode)
    front_out = bf_arr.copy()
    front_out[is_body_front] = tex_f[is_body_front]
    
    if mode == 'dark':
        front_out[is_stamp_front] = [56, 189, 248, 255]
    else:
        front_out[is_stamp_front] = [116, 46, 197, 255]
        
    img_f = Image.fromarray(front_out)
    img_f.save(f'frontend/public/pixel_mail_{mode}.png')
    img_f.save(f'frontend/src/assets/pixel_mail_{mode}.png')
    print(f'Created pixel_mail_{mode}.png')

# Generate Back Mail (734 x 529)
base_back = Image.open('frontend/public/pixel_mail_back.png')
bb_arr = np.array(base_back)

is_body_back = (bb_arr[:, :, 3] > 0) & (bb_arr[:, :, 0] > 100) & ~((bb_arr[:, :, 2] > 200) & (bb_arr[:, :, 0] < 100))
is_stamp_back = (bb_arr[:, :, 3] > 0) & (bb_arr[:, :, 2] > 200) & (bb_arr[:, :, 0] < 100)

for mode in ['dark', 'light']:
    tex_b = create_themed_texture(w_f, h_f, mode=mode)
    back_out = bb_arr.copy()
    back_out[is_body_back] = tex_b[is_body_back]
    
    if mode == 'dark':
        back_out[is_stamp_back] = [56, 189, 248, 255]
    else:
        back_out[is_stamp_back] = [116, 46, 197, 255]
        
    img_b = Image.fromarray(back_out)
    # Redraw crisp address lines on the back
    b_draw = ImageDraw.Draw(img_b)
    if mode == 'dark':
        line_color = (212, 255, 0, 255) # Neon chartreuse address lines
        sub_color = (56, 189, 248, 255) # Cyan watermark
    else:
        line_color = (116, 46, 197, 255) # Royal purple address lines
        sub_color = (147, 51, 234, 255) # Violet watermark
        
    b_draw.rectangle([100, 190, 320, 206], fill=line_color)
    b_draw.rectangle([100, 230, 480, 246], fill=line_color)
    b_draw.rectangle([100, 270, 420, 286], fill=line_color)
    b_draw.rectangle([100, 310, 350, 326], fill=line_color)
    b_draw.rectangle([100, 360, 260, 372], fill=sub_color)
    
    img_b.save(f'frontend/public/pixel_mail_back_{mode}.png')
    img_b.save(f'frontend/src/assets/pixel_mail_back_{mode}.png')
    print(f'Created pixel_mail_back_{mode}.png')

# Generate Open Back & Pocket Lip (734 x 689)
base_ob = Image.open('frontend/public/pixel_mail_open_back.png')
bob_arr = np.array(base_ob)
w_ob, h_ob = base_ob.size

base_lip = Image.open('frontend/public/pixel_mail_pocket_lip.png')
blip_arr = np.array(base_lip)

for mode in ['dark', 'light']:
    tex_tall = create_themed_texture(w_ob, h_ob, mode=mode)
    
    # 1. Open Back:
    ob_out = bob_arr.copy()
    # Body in open back includes the top open triangle and the back wall
    is_ob_body = (bob_arr[:, :, 3] > 0) & (bob_arr[:, :, 0] > 100)
    ob_out[is_ob_body] = tex_tall[is_ob_body]
    
    # Fill inner envelope cavity with futuristic interior
    cavity_y0, cavity_y1 = 205, 640
    ob_img = Image.fromarray(ob_out)
    ob_draw = ImageDraw.Draw(ob_img)
    if mode == 'dark':
        cavity_fill = (10, 14, 26, 255)
        cavity_grid = (25, 38, 64, 255)
    else:
        cavity_fill = (241, 245, 249, 255)
        cavity_grid = (218, 224, 233, 255)
        
    ob_draw.rectangle([58, cavity_y0, 622, cavity_y1], fill=cavity_fill)
    # Subtle interior chamber lines
    for y_c in range(cavity_y0 + 30, cavity_y1, 40):
        ob_draw.line([(58, y_c), (622, y_c)], fill=cavity_grid, width=2)
        
    ob_img.save(f'frontend/public/pixel_mail_open_back_{mode}.png')
    ob_img.save(f'frontend/src/assets/pixel_mail_open_back_{mode}.png')
    print(f'Created pixel_mail_open_back_{mode}.png')
    
    # 2. Pocket Lip:
    lip_out = blip_arr.copy()
    is_lip_body = (blip_arr[:, :, 3] > 0) & (blip_arr[:, :, 0] > 100) & ~((blip_arr[:, :, 2] > 200) & (blip_arr[:, :, 0] < 100))
    is_lip_stamp = (blip_arr[:, :, 3] > 0) & (blip_arr[:, :, 2] > 200) & (blip_arr[:, :, 0] < 100)
    
    lip_out[is_lip_body] = tex_tall[is_lip_body]
    if mode == 'dark':
        lip_out[is_lip_stamp] = [56, 189, 248, 255]
    else:
        lip_out[is_lip_stamp] = [116, 46, 197, 255]
        
    lip_img = Image.fromarray(lip_out)
    lip_img.save(f'frontend/public/pixel_mail_pocket_lip_{mode}.png')
    lip_img.save(f'frontend/src/assets/pixel_mail_pocket_lip_{mode}.png')
    print(f'Created pixel_mail_pocket_lip_{mode}.png')

print("All textured mail suite assets generated successfully!")
