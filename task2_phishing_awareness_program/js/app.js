/**
 * @file app.js
 * @description Main state management, navigation, and theme controller.
 * Author: CodSoft Cyber Security Intern
 */

"use strict";

const STORAGE_KEYS = {
  PROGRESS: "codsoft_phishing_progress_v1",
  THEME: "codsoft_phishing_theme",
  USER_NAME: "codsoft_learner_name",
};

/**
 * Global progress management object.
 */
const AppState = {
  /**
   * Retrieve current progress state with defensive error handling.
   * @returns {Object} Progress map of completed modules and scores.
   */
  getProgress() {
    try {
      const stored = localStorage.getItem(STORAGE_KEYS.PROGRESS);
      return stored ? JSON.parse(stored) : {};
    } catch (err) {
      console.warn("localStorage unavailable or restricted:", err);
      return {};
    }
  },

  /**
   * Mark a module as completed and save to storage.
   * @param {string} moduleId - Identifier of the module (e.g., 'lesson1').
   * @param {number} [score] - Optional quiz score attained.
   */
  markCompleted(moduleId, score = null) {
    try {
      const progress = this.getProgress();
      progress[moduleId] = {
        completed: true,
        completedAt: new Date().toISOString(),
        score: score,
      };
      localStorage.setItem(STORAGE_KEYS.PROGRESS, JSON.stringify(progress));
      this.updateProgressUI();
    } catch (err) {
      console.error("Failed to persist progress:", err);
    }
  },

  /**
   * Check if a module is marked completed.
   * @param {string} moduleId
   * @returns {boolean}
   */
  isCompleted(moduleId) {
    const progress = this.getProgress();
    return Boolean(progress[moduleId] && progress[moduleId].completed);
  },

  /**
   * Calculate overall completion percentage.
   * @returns {number} Percentage from 0 to 100.
   */
  getOverallPercentage() {
    const trackedModules = [
      "lesson1",
      "lesson2",
      "lesson3",
      "lesson4",
      "lesson5",
      "cases",
      "scenario_quiz",
      "final_assessment",
    ];
    const progress = this.getProgress();
    let completedCount = 0;
    for (const mod of trackedModules) {
      if (progress[mod] && progress[mod].completed) {
        completedCount++;
      }
    }
    return Math.round((completedCount / trackedModules.length) * 100);
  },

  /**
   * Update visual progress bars and badges on the page.
   */
  updateProgressUI() {
    const fillEl = document.getElementById("overall-progress-fill");
    const textEl = document.getElementById("overall-progress-text");
    const percent = this.getOverallPercentage();

    if (fillEl) {
      fillEl.style.width = `${percent}%`;
    }
    if (textEl) {
      textEl.textContent = `${percent}% Complete`;
    }

    // Update individual module badges if present
    const trackedModules = [
      "lesson1",
      "lesson2",
      "lesson3",
      "lesson4",
      "lesson5",
      "cases",
      "scenario_quiz",
      "final_assessment",
    ];
    const progress = this.getProgress();

    trackedModules.forEach((modId) => {
      const badge = document.getElementById(`badge-${modId}`);
      if (badge) {
        if (progress[modId] && progress[modId].completed) {
          badge.textContent = "Completed";
          badge.classList.add("completed");
        } else {
          badge.textContent = "Not Started";
          badge.classList.remove("completed");
        }
      }
    });
  },

  /**
   * Reset all progress and clear local storage.
   */
  resetAllProgress() {
    if (confirm("Are you sure you want to reset all training progress and quiz scores?")) {
      try {
        localStorage.removeItem(STORAGE_KEYS.PROGRESS);
        localStorage.removeItem(STORAGE_KEYS.USER_NAME);
        window.location.reload();
      } catch (err) {
        console.error("Error resetting progress:", err);
      }
    }
  },
};

/**
 * Theme Manager for toggling and persisting Dark/Light modes.
 */
const ThemeManager = {
  init() {
    const toggleBtn = document.getElementById("theme-toggle-btn");
    let savedTheme = null;
    try {
      savedTheme = localStorage.getItem(STORAGE_KEYS.THEME);
    } catch (e) {
      // Ignored
    }

    if (savedTheme === "dark") {
      document.body.classList.add("dark-mode");
      document.body.classList.remove("light-mode");
    } else if (savedTheme === "light") {
      document.body.classList.add("light-mode");
      document.body.classList.remove("dark-mode");
    }

    if (toggleBtn) {
      toggleBtn.addEventListener("click", () => this.toggleTheme());
    }
  },

  toggleTheme() {
    const isDark = document.body.classList.contains("dark-mode");
    if (isDark) {
      document.body.classList.remove("dark-mode");
      document.body.classList.add("light-mode");
      try {
        localStorage.setItem(STORAGE_KEYS.THEME, "light");
      } catch (e) {}
    } else {
      document.body.classList.remove("light-mode");
      document.body.classList.add("dark-mode");
      try {
        localStorage.setItem(STORAGE_KEYS.THEME, "dark");
      } catch (e) {}
    }
  },
};

// Auto-initialize when DOM is ready
document.addEventListener("DOMContentLoaded", () => {
  ThemeManager.init();
  AppState.updateProgressUI();

  const resetBtn = document.getElementById("reset-progress-btn");
  if (resetBtn) {
    resetBtn.addEventListener("click", () => AppState.resetAllProgress());
  }
});
