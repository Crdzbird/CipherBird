/** Reveals each [data-enter] block once as it scrolls into view. */
export function enterOnScroll(root = document) {
  self.cipherbirdMotion = true;
  const blocks = [...root.querySelectorAll('[data-enter]')];
  if (!('IntersectionObserver' in self) || matchMedia('(prefers-reduced-motion: reduce)').matches) {
    blocks.forEach((b) => b.classList.add('is-in'));
    return;
  }
  const watcher = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) {
        entry.target.classList.add('is-in');
        watcher.unobserve(entry.target);
      }
    }
  }, { rootMargin: '0px 0px -10% 0px' });
  blocks.forEach((b) => watcher.observe(b));
}
