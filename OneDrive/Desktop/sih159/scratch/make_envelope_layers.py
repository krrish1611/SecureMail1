from PIL import Image, ImageDraw
import numpy as np

# Load open image
open_img = Image.open('OneDrive/Desktop/sih159/frontend/public/pixel_mail_open.png').convert('RGBA')
w, h = open_img.size

# 1. Front Pocket Lip (lower half with V cut)
# cavity_y0 = 160 + 45 = 205
# V cut starts at (45, 205 + 120 = 325) -> (340, 689 - 60 = 629) -> (635, 325)
pocket_img = Image.new('RGBA', (w, h), (0, 0, 0, 0))
p_draw = ImageDraw.Draw(pocket_img)

cavity_y0 = 205
cavity_y1 = 640

pocket_poly = [
    (45, cavity_y0 + 110),
    (340, cavity_y1 - 65),
    (635, cavity_y0 + 110),
    (635, cavity_y1 + 4),
    (45, cavity_y1 + 4)
]
p_draw.polygon(pocket_poly, fill=(6, 6, 6, 255))
p_draw.polygon([
    (58, cavity_y0 + 122),
    (340, cavity_y1 - 77),
    (622, cavity_y0 + 122),
    (622, cavity_y1 - 10),
    (58, cavity_y1 - 10)
], fill=(253, 253, 253, 255))

# Shading & crease
p_draw.line([(58, cavity_y1 - 10), (340, cavity_y1 - 77)], fill=(6, 6, 6, 255), width=8)
p_draw.line([(622, cavity_y1 - 10), (340, cavity_y1 - 77)], fill=(6, 6, 6, 255), width=8)

# Blue stamp
p_draw.rectangle([540, cavity_y1 - 160, 605, cavity_y1 - 95], fill=(74, 144, 226, 255), outline=(6, 6, 6, 255), width=8)

pocket_img.save('OneDrive/Desktop/sih159/frontend/public/pixel_mail_pocket_lip.png')
print("Saved pixel_mail_pocket_lip.png")

# 2. Back & Open Flap (everything behind the letter)
open_back = open_img.copy()
# Clear front pocket from open_back so it's only back wall and top open flap
b_arr = np.array(open_back)
# Fill cavity with soft grey interior:
b_draw = ImageDraw.Draw(open_back)
b_draw.rectangle([58, cavity_y0, 622, cavity_y1], fill=(226, 232, 240, 255))
open_back.save('OneDrive/Desktop/sih159/frontend/public/pixel_mail_open_back.png')
print("Saved pixel_mail_open_back.png")
