/**
 * @file quiz.js
 * @description Dynamic quiz engine, scenario validator, and certificate generator.
 * Author: CodSoft Cyber Security Intern
 */

"use strict";

/**
 * Quiz Engine Class
 */
class QuizEngine {
  /**
   * @param {string} containerId - Element ID of container to render quiz in.
   * @param {Array<Object>} questions - List of question objects from QUIZ_DATA.
   * @param {string} moduleId - Associated module ID for progress tracking.
   * @param {number} [passThreshold=70] - Percentage required to pass.
   * @param {Function} [onComplete] - Callback executed upon completion.
   */
  constructor(containerId, questions, moduleId, passThreshold = 70, onComplete = null) {
    this.container = document.getElementById(containerId);
    this.questions = questions || [];
    this.moduleId = moduleId;
    this.passThreshold = passThreshold;
    this.onComplete = onComplete;
    this.userAnswers = new Array(this.questions.length).fill(null);
    this.submitted = false;

    if (this.container && this.questions.length > 0) {
      this.render();
    }
  }

  render() {
    this.container.innerHTML = ""; // Clear existing

    const header = document.createElement("div");
    header.className = "quiz-header";

    const title = document.createElement("h3");
    title.textContent = `Knowledge Check: ${this.questions.length} Questions`;
    const desc = document.createElement("p");
    desc.style.color = "var(--text-muted)";
    desc.textContent = "Select the best answer for each question. Instant feedback and explanations will be revealed upon submission.";

    header.appendChild(title);
    header.appendChild(desc);
    this.container.appendChild(header);

    // Render questions
    this.questions.forEach((q, qIndex) => {
      const qCard = document.createElement("div");
      qCard.className = "question-card";
      qCard.id = `q-card-${qIndex}`;

      const qText = document.createElement("div");
      qText.className = "question-text";
      qText.textContent = `${qIndex + 1}. ${q.question}`;
      qCard.appendChild(qText);

      const optionsList = document.createElement("div");
      optionsList.className = "options-list";

      q.options.forEach((optText, optIndex) => {
        const optBtn = document.createElement("div");
        optBtn.className = "option-item";
        optBtn.id = `opt-${qIndex}-${optIndex}`;

        const radio = document.createElement("input");
        radio.type = "radio";
        radio.name = `question_${qIndex}`;
        radio.id = `input-${qIndex}-${optIndex}`;
        radio.checked = this.userAnswers[qIndex] === optIndex;

        const label = document.createElement("span");
        label.textContent = optText;

        optBtn.appendChild(radio);
        optBtn.appendChild(label);

        optBtn.addEventListener("click", () => {
          if (!this.submitted) {
            this.selectOption(qIndex, optIndex);
          }
        });

        optionsList.appendChild(optBtn);
      });

      qCard.appendChild(optionsList);

      const explBox = document.createElement("div");
      explBox.className = "explanation-box";
      explBox.id = `expl-${qIndex}`;
      qCard.appendChild(explBox);

      this.container.appendChild(qCard);
    });

    // Action buttons
    const actionContainer = document.createElement("div");
    actionContainer.style.display = "flex";
    actionContainer.style.gap = "1rem";
    actionContainer.style.marginTop = "2rem";

    const submitBtn = document.createElement("button");
    submitBtn.className = "btn btn-primary";
    submitBtn.id = "quiz-submit-btn";
    submitBtn.textContent = "Submit Answers";
    submitBtn.addEventListener("click", () => this.submit());

    actionContainer.appendChild(submitBtn);
    this.container.appendChild(actionContainer);
  }

  selectOption(qIndex, optIndex) {
    this.userAnswers[qIndex] = optIndex;
    this.questions[qIndex].options.forEach((_, idx) => {
      const optEl = document.getElementById(`opt-${qIndex}-${idx}`);
      const inputEl = document.getElementById(`input-${qIndex}-${idx}`);
      if (optEl && inputEl) {
        if (idx === optIndex) {
          optEl.classList.add("selected");
          inputEl.checked = true;
        } else {
          optEl.classList.remove("selected");
          inputEl.checked = false;
        }
      }
    });
  }

  submit() {
    // Check if all answered
    const unanswered = this.userAnswers.findIndex((ans) => ans === null);
    if (unanswered !== -1) {
      alert(`Please answer Question #${unanswered + 1} before submitting.`);
      return;
    }

    this.submitted = true;
    let correctCount = 0;

    this.questions.forEach((q, qIndex) => {
      const chosen = this.userAnswers[qIndex];
      const isCorrect = chosen === q.correctAnswer;
      if (isCorrect) correctCount++;

      // Style options
      q.options.forEach((_, optIndex) => {
        const optEl = document.getElementById(`opt-${qIndex}-${optIndex}`);
        if (!optEl) return;
        optEl.style.cursor = "default";
        if (optIndex === q.correctAnswer) {
          optEl.classList.add("correct");
        } else if (optIndex === chosen && !isCorrect) {
          optEl.classList.add("incorrect");
        }
      });

      // Show explanation
      const explEl = document.getElementById(`expl-${qIndex}`);
      if (explEl) {
        explEl.className = `explanation-box ${isCorrect ? "correct" : "incorrect"}`;
        explEl.textContent = `${isCorrect ? "✔ Correct! " : "✘ Incorrect. "}${q.explanation}`;
      }
    });

    const percent = Math.round((correctCount / this.questions.length) * 100);
    const passed = percent >= this.passThreshold;

    // Show summary
    const summaryCard = document.createElement("div");
    summaryCard.className = "quiz-score-summary";

    const scoreTitle = document.createElement("h2");
    scoreTitle.textContent = passed ? "🎉 Quiz Passed!" : "⚠️ Passing Threshold Not Met";
    scoreTitle.style.color = passed ? "var(--success)" : "var(--danger)";

    const scoreDisp = document.createElement("div");
    scoreDisp.className = "score-display";
    scoreDisp.textContent = `${percent}%`;

    const scoreText = document.createElement("p");
    scoreText.style.color = "var(--text-muted)";
    scoreText.textContent = `You answered ${correctCount} of ${this.questions.length} questions correctly. Passing score: ${this.passThreshold}%.`;

    summaryCard.appendChild(scoreTitle);
    summaryCard.appendChild(scoreDisp);
    summaryCard.appendChild(scoreText);

    if (passed) {
      AppState.markCompleted(this.moduleId, percent);
    }

    // Replace submit button with retry or next button
    const submitBtn = document.getElementById("quiz-submit-btn");
    if (submitBtn) {
      submitBtn.remove();
    }

    const retryBtn = document.createElement("button");
    retryBtn.className = "btn btn-secondary";
    retryBtn.textContent = "Retry Quiz";
    retryBtn.addEventListener("click", () => {
      this.submitted = false;
      this.userAnswers = new Array(this.questions.length).fill(null);
      this.render();
    });
    summaryCard.appendChild(retryBtn);

    this.container.appendChild(summaryCard);

    if (this.onComplete) {
      this.onComplete({ passed, score: percent, correctCount, total: this.questions.length });
    }
  }
}

/**
 * Certificate Generator
 */
const CertificateService = {
  renderCertificate(containerId, learnerName, score) {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.innerHTML = "";

    const certWrapper = document.createElement("div");
    certWrapper.className = "certificate-container";

    const borderInner = document.createElement("div");
    borderInner.className = "cert-border-inner";

    const header = document.createElement("h1");
    header.className = "cert-header";
    header.textContent = "Certificate of Completion";

    const sub = document.createElement("p");
    sub.className = "cert-sub";
    sub.textContent = "CodSoft Cyber Security Awareness & Defensive Hygiene Program";

    const presentedTo = document.createElement("p");
    presentedTo.className = "cert-presented-to";
    presentedTo.textContent = "THIS IS PROUDLY PRESENTED TO";

    const nameEl = document.createElement("div");
    nameEl.className = "cert-name";
    // SECURE: Use textContent to prevent XSS
    nameEl.textContent = learnerName.trim() || "Security Champion";

    const desc = document.createElement("p");
    desc.className = "cert-desc";
    desc.textContent = `For successfully mastering the Phishing Awareness Training curriculum, demonstrating proficiency in detecting social engineering vectors, identifying lookalike domains, analyzing unencrypted web flows, and scoring ${score}% on the Comprehensive Security Assessment.`;

    const footerRow = document.createElement("div");
    footerRow.className = "cert-footer-row";

    const dateBlock = document.createElement("div");
    dateBlock.className = "cert-sig-block";
    const today = new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
    dateBlock.textContent = `Date of Issue: ${today}`;

    const sigBlock = document.createElement("div");
    sigBlock.className = "cert-sig-block";
    sigBlock.textContent = "CodSoft Security Mentor";

    footerRow.appendChild(dateBlock);
    footerRow.appendChild(sigBlock);

    borderInner.appendChild(header);
    borderInner.appendChild(sub);
    borderInner.appendChild(presentedTo);
    borderInner.appendChild(nameEl);
    borderInner.appendChild(desc);
    borderInner.appendChild(footerRow);

    certWrapper.appendChild(borderInner);
    container.appendChild(certWrapper);

    const btnRow = document.createElement("div");
    btnRow.className = "no-print";
    btnRow.style.textAlign = "center";
    btnRow.style.marginTop = "1.5rem";

    const printBtn = document.createElement("button");
    printBtn.className = "btn btn-primary";
    printBtn.textContent = "🖨️ Print or Save as PDF";
    printBtn.addEventListener("click", () => window.print());

    btnRow.appendChild(printBtn);
    container.appendChild(btnRow);
  }
};
