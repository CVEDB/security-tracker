;;; cvelist --- Major mode for Debian's CVE list
;;;
;;; Commentary:
;;;   only useful for security-tracker-team/security-tracker.git's data/CVE/list
;;;
;;; Code:
;;;   Guido Günther
;;;   Moritz Muehlenhoff
;;;   Sébastien Delafond
;;;
;;; Can be enabled via:
;;;
;;; (autoload 'debian-cvelist-mode "cvelist.el"
;;;     "Major mode for debian CVE lists" t)
;;; (setq auto-mode-alist
;;;     (cons '("list" . debian-cvelist-mode) auto-mode-alist))

(setq last-nfu "")
(setq bugnum "")
(setq newsrcpkg "")
(setq default_distro "bullseye")

; TODO: Tab completion for existing NFUs
(defun debian-cvelist-insert-not-for-us ()
  "Insert NOT-FOR-US keyword."
  (setq last-nfu (read-string "Name of software: " last-nfu))
  (interactive)
  (beginning-of-line)
  (kill-whole-line)
  (insert "\tNOT-FOR-US: " last-nfu "\n" ))

(defun debian-cvelist-insert-note ()
  "Insert NOTE comment."
  (interactive)
  (insert "\tNOTE: "))

(defun debian-cvelist-insert-bug ()
  "Add bugnumber to end of line."
  (setq bugnum (read-string "Bug number (without #): " bugnum))
  (interactive)
  (end-of-line)
  (insert " (bug #" bugnum ")" ))

; TODO: Read supported distros from central config and prompt for applicable suites
(defun debian-cvelist-insert-nodsa ()
  "Insert no-dsa comment based on the current source entry."
  (interactive)
  (setq reason (read-string "Reason for no-dsa: " "Minor issue"))
  (setq srcpkg (thing-at-point 'filename))
  (next-line)
  (beginning-of-line)
  (insert (concat "\t[" default_distro "] - " srcpkg " <no-dsa> (" reason ")\n" )))

(defun debian-cvelist-insert-postponed ()
  "Insert postponed comment based on the current source entry."
  (interactive)
  (setq reason (read-string "Reason for postponed: " "Minor issue, fix along with next update"))
  (setq srcpkg (thing-at-point 'filename))
  (next-line)
  (beginning-of-line)
  (insert (concat "\t[" default_distro "] - " srcpkg " <postponed> (" reason ")\n" )))

; TODO: Read supported distros from central config and prompt for applicable suites
(defun debian-cvelist-insert-not-affected ()
  "Insert not-affected comment based on the current source entry."
  (interactive)
  (setq reason (read-string "Reason for not-affected: " "Vulnerable code not present"))
  (setq srcpkg (thing-at-point 'filename))
  (next-line)
  (beginning-of-line)
  (insert (concat "\t[" default_distro "] - " srcpkg " <not-affected> (" reason ")\n" )))

; TODO: Parse existing source entries for buffer tab completion
(defun debian-cvelist-insert-srcentry ()
  "Insert new source package entry."
  (interactive)
  (setq newsrcpkg (read-string "Source package: " newsrcpkg))
  (setq version (read-string "Fixed version: " "<unfixed>"))
  (next-line)
  (beginning-of-line)
  (insert (concat "\t- " newsrcpkg " " version "\n")))

(defun debian-cvelist-cvesearch ()
  "Look up a CVE ID at the MITRE website."
  (interactive)
  (browse-url (concat "https://www.cve.org/CVERecord?id=" (thing-at-point 'symbol))))

(defun debian-cvelist-ptslookup ()
  "Look up a package name in Debian Package Tracker."
  (interactive)
  (browse-url (concat "https://tracker.debian.org/pkg/" (thing-at-point 'symbol))))

(defvar debian-cvelist-mode-map
   (let ((map (make-sparse-keymap)))
     (define-key map (kbd "C-c C-f") 'debian-cvelist-insert-not-for-us)
     (define-key map (kbd "C-c C-n") 'debian-cvelist-insert-note)
     (define-key map (kbd "C-c C-c") 'debian-cvelist-cvesearch)
     (define-key map (kbd "C-c C-l") 'debian-cvelist-insert-nodsa)
     (define-key map (kbd "C-c C-a") 'debian-cvelist-insert-srcentry)
     (define-key map (kbd "C-c C-x") 'debian-cvelist-insert-not-affected)
     (define-key map (kbd "C-c C-p") 'debian-cvelist-insert-postponed)
     (define-key map (kbd "C-c C-b") 'debian-cvelist-insert-bug)
     (define-key map (kbd "C-c C-p") 'debian-cvelist-ptslookup)
     map)
   "Keymap for `debian-cvelist-mode'.")

(defvar debian-cvelist-font-lock-keywords
  '(("^CVE-[0-9]\\{4\\}-[0-9X]\\{4,7\\}"
     (0 font-lock-function-name-face) ;; face for CVE keyword
     ("(\\(.+\\))$" nil nil (1 font-lock-warning-face))) ;; face for the rest of the line
    ("D[LS]A-[0-9]\\{4,5\\}-[0-9]" . font-lock-function-name-face)
    ("#[0-9]\\{1,7\\}" . font-lock-type-face)
    ("^\tNOTE:" . font-lock-comment-delimiter-face)
    ("^\tTODO:" . font-lock-warning-face)
    ("^\t\\(RESERVED\\|NOT-FOR-US\\|REJECTED\\)" . font-lock-keyword-face)
    ("\\<unfixed\\|undetermined\\>" . font-lock-warning-face)
    ("\\<end-of-life\\|not-affected\\|no-dsa\\|ignored\\|postponed\\>" . font-lock-constant-face))
  "Keyword highlighting for `debian-cvelist-mode'.")

(defun debian-cvelist-is-cve ()
  "Checks if a current line is a CVE description."
  (save-excursion
    (beginning-of-line)
    (looking-at "[[:space:]]*CVE-")))

(defun debian-cvelist-indent-line ()
  "Indent current line as debian CVE list."
  (beginning-of-line)
  (if (debian-cvelist-is-cve)
      (indent-line-to 0)
    (indent-line-to 8)))

(define-derived-mode debian-cvelist-mode fundamental-mode "debian-cvelist"
  "A major mode for editing data/CVE/list in the Debian
   secure-tracker repository."
  (setq-local font-lock-defaults '(debian-cvelist-font-lock-keywords t))
  (setq-local indent-line-function 'debian-cvelist-indent-line))

(provide 'debian-cvelist)
;;; cvelist.el ends here
