import { fileURLToPath } from 'node:url';
import sharp from 'sharp';

const source = new URL('../src/assets/bifrost-social-card.svg', import.meta.url);
const output = new URL('../public/bifrost-social-card.png', import.meta.url);

await sharp(fileURLToPath(source)).resize(1200, 630).png().toFile(fileURLToPath(output));
