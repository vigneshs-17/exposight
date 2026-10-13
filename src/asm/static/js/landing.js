/**
 * Landing page pointer tilt (C-UI-1).
 * All other motion is CSS (landing.css). This only sets CSS custom properties
 * (--rx, --ry, --mx, --my) on .tilt elements through style.setProperty, which the
 * strict CSP allows. Off for reduced motion and for touch/coarse pointers.
 * No setAttribute('style'), no DOM html injection.
 */

document.addEventListener("DOMContentLoaded", function () {
  var finePointer = window.matchMedia("(hover: hover) and (pointer: fine)");
  var reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  var MAX_DEG = 7;

  function reset(el) {
    el.style.setProperty("--rx", "0deg");
    el.style.setProperty("--ry", "0deg");
  }

  document.querySelectorAll(".tilt").forEach(function (el) {
    el.addEventListener("pointermove", function (event) {
      if (!finePointer.matches || reducedMotion.matches) {
        return;
      }
      var rect = el.getBoundingClientRect();
      var x = (event.clientX - rect.left) / rect.width;
      var y = (event.clientY - rect.top) / rect.height;
      el.style.setProperty("--ry", ((x - 0.5) * 2 * MAX_DEG).toFixed(2) + "deg");
      el.style.setProperty("--rx", ((0.5 - y) * 2 * MAX_DEG).toFixed(2) + "deg");
      el.style.setProperty("--mx", (x * 100).toFixed(1) + "%");
      el.style.setProperty("--my", (y * 100).toFixed(1) + "%");
    });
    el.addEventListener("pointerleave", function () {
      reset(el);
    });
  });
});
