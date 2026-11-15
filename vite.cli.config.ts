import { defineConfig } from 'vite'

/**
 * Construit la commande `fortiscope` pour la CI : un seul fichier Node autonome (dépendances incluses),
 * qu'on peut copier dans le dépôt des configurations ou publier comme artefact de release.
 */
export default defineConfig({
  build: {
    ssr: 'src/cli/fortiscope.ts',
    outDir: 'dist-cli',
    emptyOutDir: true,
    target: 'node20',
    minify: false,
    rollupOptions: {
      output: {
        entryFileNames: 'fortiscope.mjs',
        banner: '#!/usr/bin/env node',
      },
    },
  },
  ssr: {
    noExternal: true,
    target: 'node',
  },
})
