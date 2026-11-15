// Exécuté avant l'application (script classique, autorisé par la CSP 'self') :
// 1. recopie les préférences enregistrées sous l'ancien nom (fortiscope-*) vers le nouveau (shadowline-*) ;
// 2. applique le thème avant le premier rendu, pour éviter un flash clair en thème sombre.
// Les préfixes doivent rester identiques à STORAGE_PREFIX / LEGACY_STORAGE_PREFIX de src/brand.ts.
(function () {
  var prefix = 'shadowline-'
  var legacyPrefix = 'fortiscope-'
  try {
    var legacyKeys = []
    for (var index = 0; index < localStorage.length; index += 1) {
      var key = localStorage.key(index)
      if (key && key.indexOf(legacyPrefix) === 0) legacyKeys.push(key)
    }
    legacyKeys.forEach(function (key) {
      var renamed = prefix + key.slice(legacyPrefix.length)
      if (localStorage.getItem(renamed) === null) localStorage.setItem(renamed, localStorage.getItem(key))
      localStorage.removeItem(key)
    })
  } catch (error) { /* stockage indisponible : rien à migrer */ }
  try {
    var theme = localStorage.getItem(prefix + 'theme')
    document.documentElement.dataset.theme = theme === 'dark' || theme === 'light'
      ? theme
      : (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
  } catch (error) { /* thème par défaut du CSS */ }
})()
