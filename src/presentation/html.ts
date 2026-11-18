/** Échappement HTML unique pour tout texte inséré dans du HTML (texte, attributs entre guillemets simples ou doubles). */
export const escapeHtml = (value: string): string =>
  value.replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[character] ?? character)
