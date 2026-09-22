from PIL import Image
import os

# Set the input and output directories.
input_dir = 'path/to/your/icons'  # Replace with your icon folder path.
output_image_path = 'path/to/output/combined_image.png'  # Replace with the path where you want to save the combined image.

# Set thumbnail size
thumbnail_size = (100, 100)  # You can adjust this size as needed.

# Get all .png files
png_files = [f for f in os.listdir(input_dir) if f.endswith('.png')]

# Calculate the size of the merged image.
num_files = len(png_files)
num_cols = 10  # Number of thumbnails displayed per row.
num_rows = (num_files + num_cols - 1) // num_cols

# Create a blank image to hold all thumbnails.
combined_image = Image.new('RGB', (num_cols * thumbnail_size[0], num_rows * thumbnail_size[1]), (255, 255, 255))

# Iterate over all .png files, generate thumbnails, and paste them into the merged image.
for i, filename in enumerate(png_files):
    file_path = os.path.join(input_dir, filename)
    with Image.open(file_path) as img:
        img.thumbnail(thumbnail_size)
        x = (i % num_cols) * thumbnail_size[0]
        y = (i // num_cols) * thumbnail_size[1]
        combined_image.paste(img, (x, y))

# Save combined image
combined_image.save(output_image_path)

print(f"Combined image saved to {output_image_path}")
