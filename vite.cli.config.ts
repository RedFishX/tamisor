import { defineConfig } from 'vite'

/**
 * Construit la commande `shadowline` pour la CI : un seul fichier Node autonome (dépendances incluses),
 * qu'on peut copier dans le dépôt des configurations ou publier comme artefact de release.
 */
export default defineConfig({
  publicDir: false,
  build: {
    ssr: 'src/cli/shadowline.ts',
    outDir: 'dist-cli',
    emptyOutDir: true,
    target: 'node20',
    minify: false,
    rollupOptions: {
      output: {
        entryFileNames: 'shadowline.mjs',
        banner: '#!/usr/bin/env node',
      },
    },
  },
  ssr: {
    noExternal: true,
    target: 'node',
  },
})
