from PIL import Image, ImageDraw, ImageFont
import numpy as np

# Load original pixel mail
orig = Image.open('OneDrive/Desktop/sih159/frontend/public/pixel_mail.png').convert('RGBA')
arr = np.array(orig)
w, h = orig.size

print("Original image size:", w, h)

# 1. Let's find the V-seam
# The V seam consists of the diagonal line of black pixels separating the top flap from the bottom pocket.
# Let's inspect column by column to find the flap boundary.
# For each column x, find the y of the V crease line:
# From x=48 to x=367: y steps from ~48 down to ~304
# From x=367 to x=683: y steps from ~304 up to ~160 (or under stamp)

# Let's create a mask for the flap (region above the V seam)
flap_mask = np.zeros((h, w), dtype=bool)

# Let's trace the seam:
# In each column, find the black pixel corresponding to the V fold:
for x in range(w):
    # For each column, find all black pixels
    black_ys = np.where((arr[:, x, 0] < 50) & (arr[:, x, 3] > 200))[0]
    if len(black_ys) == 0:
        continue
    
    # We know the top border is around y <= 48
    # The bottom border is around y >= 450
    # The V crease is between y=48 and y=330
    v_cand = [y for y in black_ys if 45 <= y <= 330]
    if v_cand:
        # Seam line is at max(v_cand) (the lower edge of the black seam line)
        seam_y = max(v_cand)
        # Everything from y=0 down to seam_y is part of the top flap
        flap_mask[:seam_y+1, x] = True

# Also include the grey shadow immediately below the V seam in the flap if desired,
# or let the flap have the black line, and pocket have the grey shadow!
# Let's make flap:
flap_arr = arr.copy()
flap_arr[~flap_mask] = 0 # zero out pocket
flap_img = Image.fromarray(flap_arr)
flap_img.save('OneDrive/Desktop/sih159/frontend/public/pixel_mail_flap.png')
print("Saved pixel_mail_flap.png")

# Pocket:
pocket_arr = arr.copy()
# Pocket is everything below the flap (and the outer borders)
pocket_mask = ~flap_mask
# But pocket should also retain the left, right, and bottom borders
# Let's keep outer border:
for x in range(w):
    # top border is part of back/flap
    pass
pocket_arr[flap_mask] = 0
pocket_img = Image.fromarray(pocket_arr)
pocket_img.save('OneDrive/Desktop/sih159/frontend/public/pixel_mail_pocket.png')
print("Saved pixel_mail_pocket.png")

