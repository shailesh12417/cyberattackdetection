(function () {
  const canvas = document.getElementById('particlesCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let width, height, particles = [], animId;
  const mouse = { x: null, y: null, radius: 160 };
  const COUNT = 70;
  const CONNECT_DIST = 150;

  function resize() { width = canvas.width = window.innerWidth; height = canvas.height = window.innerHeight; }

  class Particle {
    constructor() { this.reset(); }
    reset() {
      this.x = Math.random() * width;
      this.y = Math.random() * height;
      this.vx = (Math.random() - 0.5) * 0.4;
      this.vy = (Math.random() - 0.5) * 0.4;
      this.size = Math.random() * 2 + 0.8;
      this.baseOpacity = Math.random() * 0.4 + 0.15;
      this.opacity = this.baseOpacity;
      this.hue = Math.random() > 0.5 ? 186 : 270; // cyan or purple
    }
    update() {
      if (mouse.x !== null) {
        const dx = mouse.x - this.x, dy = mouse.y - this.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < mouse.radius) {
          const force = (mouse.radius - dist) / mouse.radius;
          this.vx += (dx / dist) * force * 0.015;
          this.vy += (dy / dist) * force * 0.015;
          this.opacity = Math.min(0.8, this.baseOpacity + force * 0.5);
        } else { this.opacity += (this.baseOpacity - this.opacity) * 0.05; }
      }
      this.vx *= 0.995; this.vy *= 0.995;
      this.x += this.vx; this.y += this.vy;
      if (this.x < -10) this.x = width + 10;
      if (this.x > width + 10) this.x = -10;
      if (this.y < -10) this.y = height + 10;
      if (this.y > height + 10) this.y = -10;
    }
    draw() {
      const isLight = document.documentElement.getAttribute('data-theme') === 'light';
      const dim = isLight ? 0.35 : 1;
      const color = this.hue === 186 ? `rgba(6,182,212,${this.opacity * dim})` : `rgba(168,85,247,${this.opacity * dim})`;
      const glow = this.hue === 186 ? `rgba(6,182,212,${this.opacity * 0.12 * dim})` : `rgba(168,85,247,${this.opacity * 0.12 * dim})`;
      ctx.beginPath(); ctx.arc(this.x, this.y, this.size * 2.5, 0, Math.PI * 2);
      ctx.fillStyle = glow; ctx.fill();
      ctx.beginPath(); ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
      ctx.fillStyle = color; ctx.fill();
    }
  }

  function init() { particles = []; for (let i = 0; i < COUNT; i++) particles.push(new Particle()); }

  function connections() {
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x, dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < CONNECT_DIST) {
          const isLight = document.documentElement.getAttribute('data-theme') === 'light';
          const o = (1 - dist / CONNECT_DIST) * (isLight ? 0.04 : 0.12);
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = `rgba(139,92,246,${o})`;
          ctx.lineWidth = 0.6;
          ctx.stroke();
        }
      }
    }
  }

  function animate() {
    ctx.clearRect(0, 0, width, height);
    particles.forEach(p => { p.update(); p.draw(); });
    connections();
    animId = requestAnimationFrame(animate);
  }

  window.addEventListener('resize', resize);
  canvas.addEventListener('mousemove', e => { mouse.x = e.clientX; mouse.y = e.clientY; });
  canvas.addEventListener('mouseleave', () => { mouse.x = null; mouse.y = null; });

  resize(); init(); animate();
})();
