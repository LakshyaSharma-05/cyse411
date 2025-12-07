app.get('/search', (req, res) => {
  const q = req.query.q || '';
  const escapeHtml = (text) => {
    return text.replace(/[&<>"']/g, (char) => {
      const entities = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
      };
      return entities[char];
    });
  };
  res.send(`<h1>Results for ${escapeHtml(q)}</h1>`);
});
