;;;;
;;;; rfc.smtp module.
;;;;  2010, Hayato Hashimoto
;;;;
;;;;  Delivered from "rfc.imap4 module" written by
;;;;   Copyright (c) 2005-2007, SHIINO Yuki, All rights reserved.
;;;;
;;;;  Redistribution and use in source and binary forms, with or without
;;;;  modification, are permitted provided that the following conditions
;;;;  are met:
;;;;
;;;;   1. Redistributions of source code must retain the above copyright
;;;;      notice, this list of conditions and the following disclaimer.
;;;;
;;;;   2. Redistributions in binary form must reproduce the above copyright
;;;;      notice, this list of conditions and the following disclaimer in the
;;;;      documentation and/or other materials provided with the distribution.
;;;;
;;;;   3. Neither the name of the authors nor the names of its contributors
;;;;      may be used to endorse or promote products derived from this
;;;;      software without specific prior written permission.
;;;;
;;;;  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;;;;  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;;;;  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;;;;  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;;;;  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;;;;  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
;;;;  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
;;;;  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
;;;;  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;;;  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;;;  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;;

;; COVERAGE: 
;;    RFC SMTP
;;    RFC ESMTP
;;    RFC 4954 SMTP Service Extension for Authentication


(define-module rfc.smtp
  (use gauche.collection)
  (use gauche.net)
  (use gauche.regexp)
  (use gauche.uvector)
  (use rfc.base64)
  (use rfc.hmac)
  (use rfc.md5)
  (use srfi-1)
  (use srfi-13)
  (use srfi-19)

  (export <smtp> smtp-escape-data

		  smtp-connect
		  smtp-disconnect
		  smtp-shutdown
		  smtp-authenticate

		  smtp-tag-formatter
		  smtp-input-logger
		  smtp-output-logger

		  smtp-quote-string
		  smtp-unquote-string

		  smtp.data
		  smtp.mail.from
		  smtp.rcpt.to
		  smtp.noop
		  smtp.rset
                  smtp.bdat
                  smtp.turn
                  smtp.atrn
                  smtp.etrn
                  smtp.vrfy
                  smtp.expn
                  smtp.help
                  smtp.soml
                  smtp.saml

		  <smtp-error>
		  smtp-error?
		  <smtp-error-reply-no>
		  smtp-error-reply-no?
		  <smtp-error-reply-bad>
		  smtp-error-reply-bad?
		  ))
(select-module rfc.smtp)

(define-class <smtp> ()
  ((host :init-keyword :host :init-value "127.0.0.1" :getter host-of)
   (port :init-keyword :port :init-value 587 :getter port-of)
   (sock :getter socket-of)
   (tag-count :init-value 0)
   (tag-formatter :init-value number->string :accessor smtp-tag-formatter)
   (input-logger :init-value (lambda (log) ()) :accessor smtp-input-logger)
   (output-logger :init-value (lambda (log) ()) :accessor smtp-output-logger)))

;; General error condition.
(define-condition-type <smtp-error> <error>
  smtp-error?)
;; NO server reply.
(define-condition-type <smtp-error-reply-no> <smtp-error>
  smtp-error-reply-no?)
;; BAD server reply.
(define-condition-type <smtp-error-reply-bad> <smtp-error>
  smtp-error-reply-bad?)

(define-method smtp-connect ((self <smtp>) . host.port)
  (let-optionals* host.port ((host (host-of self)) (port (port-of self)))
				  (slot-set! self 'host host)
				  (slot-set! self 'port port))
  (guard (e
    ((<error> e) (error <io-error> 
     (format "Failed to open socket to ~a:~d" (host-of self) (port-of self)))))
   (slot-set! self 'sock (make-client-socket (host-of self) (port-of self))))
  (recv-resp self "220")
  (send-command self "EHLO" "localhost")
  (recv-resp self "250")
)

;; Send QUIT and shutdown...
(define-method smtp-disconnect ((self <smtp>))
  (send-command self "QUIT")
  (recv-resp self "221")
  (smtp-shutdown self))

;; Immediate shutdown...
(define-method smtp-shutdown ((self <smtp>))
  (socket-shutdown (socket-of self) 2)
  (socket-close (socket-of self))
  (values))

(define-method smtp-authenticate ((self <smtp>) user password mechanism)
  (case mechanism
        ((plain)
         (smtp-auth-plain self user password))
	((login)
	 (smtp-auth-login self user password))
	((cram-md5)
	 (smtp-auth-cram-md5 self user password))
	(else
	 (error <smtp-error> "Unsupported authentication mechanism : " mechanism))))

(define-method smtp-auth-plain ((self <smtp>) user password)
  (send-command self "AUTH" "PLAIN")
  (recv-resp self)
  (send-command self (base64-encode-string (format "~a\0~a\0~a" user user password)))
  (recv-resp self "235"))

(define-method smtp-auth-login ((self <smtp>) user password)
  (error <smtp-error> "Unsupported auth login"))

(define-method smtp-auth-cram-md5 ((self <smtp>) user password)
  (error <smtp-error> "Unsupported auth login"))

(define (smtp-escape-data str)
  (string-append (regexp-replace (string->regexp "\n\\.") str "\n..") "\r\n."))

(define (smtp-quote-string str)
  (if (not str)
	  "NIL"
	  (with-string-io
	   str
	   (lambda ()
		 (write-char #\")
		 (let loop ((c (read-char)))
		   (cond ((eof-object? c))
				 ((or (char=? c #\\) (char=? c #\"))
				  (write-char #\\)
				  (write-char c)
				  (loop (read-char)))
				 (else
				  (write-char c)
				  (loop (read-char)))))
		 (write-char #\")))))

(define (smtp-unquote-string str)
  (cond
   ((string-ci=? str "NIL")
	#f)
   ((not (#/^\".*\"$/ str))
	str)
   (else
	(with-string-io
	 (substring str 1 (- (string-length str) 1))
	 (lambda ()
	   (define (in-plain c)
		 (cond ((eof-object? c))
			   ((char=? c #\\)
				(follow-backslash (read-char)))
			   (else
				(write-char c)
				(in-plain (read-char)))))
	   (define (follow-backslash c)
		 (cond ((eof-object? c)
				(write-char #\\))
			   ((or (char=? c #\\) (char=? c #\"))
				(write-char c)
				(in-plain (read-char)))
			   (else
				(write-char #\\)
				(write-char c)
				(in-plain (read-char)))))
	   (in-plain (read-char)))))))


(define-method smtp.noop ((self <smtp>))
  (send-command self "NOOP")
  (recv-resp self "250"))

(define-method smtp.mail.from ((self <smtp>) from . args)
  (apply send-command self "MAIL FROM:" from args)
  (recv-resp self "250"))

(define-method smtp.rcpt.to ((self <smtp>) to . args)
  (apply send-command self "RCPT TO:" to args)
  (recv-resp self "250"))

(define-method smtp.data ((self <smtp>) data)
  (send-command self "DATA") 
  (recv-resp self "354")
  (send-command self (smtp-escape-data data))
  (recv-resp self "250"))

(define-method smtp.rset ((self <smtp>))
  (send-command self "RSET")
  (recv-resp self "250"))

(define-method smtp.bdat ((self <smtp>))
  (error <smtp-error> "Unsupported command"))

(define-method smtp.turn ((self <smtp>))
  (error <smtp-error> "Unsupported command"))

(define-method smtp.expn ((self <smtp>))
  (error <smtp-error> "Unsupported command"))

(define-method smtp.atrn ((self <smtp>))
  (error <smtp-error> "Unsupported command"))

(define-method smtp.help ((self <smtp>))
  (error <smtp-error> "Unsupported command"))

(define-method smtp.saml ((self <smtp>))
  (error <smtp-error> "Unsupported command"))

(define-method smtp.soml ((self <smtp>))
  (error <smtp-error> "Unsupported command"))

(define-method smtp.vrfy ((self <smtp>))
  (error <smtp-error> "Unsupported command"))

(define-method smtp.etrn ((self <smtp>))
  (error <smtp-error> "Unsupported command"))

;; Private methods and routines for the implementation.
(define-method input-port-of ((self <smtp>) . keywords)
  (apply socket-input-port (socket-of self) keywords))

(define-method output-port-of ((self <smtp>) . keywords)
  (apply socket-output-port (socket-of self) keywords))

(define-method tag-of ((self <smtp>))
  ((smtp-tag-formatter self) (slot-ref self 'tag-count)))

(define-method regexp-with-tag ((self <smtp>) expected)
  (string->regexp (string-append "^" (tag-of self) " " expected "( |$)") :case-fold #t))

(define-method send-line ((self <smtp>) line)
  (display (string-append line "\r\n") (output-port-of self))
  (flush (output-port-of self))
  ((smtp-output-logger self) line))

(define-method send-literal ((self <smtp>) literal)
  (write-block literal (output-port-of self))
  (flush (output-port-of self))
  ((smtp-output-logger self) literal))

(define-method send-command ((self <smtp>) command . args)
  (let ((cmd (if (null? args) 
				 command
				 (string-append command " " (string-join args)))))
	(inc! (slot-ref self 'tag-count))
	(send-line self cmd)))

(define-method recv-line ((self <smtp>))
  (let ((line (read-line (input-port-of self))))
	(when (not (eof-object? line))
	  ((smtp-input-logger self) line))
	line))

(define-method recv-literal ((self <smtp>) num-of-bytes)
  (let ((literal (make-u8vector num-of-bytes)))
	(let loop ((nbytes 0))
	  (if (< nbytes num-of-bytes)
		  (let ((n (read-block! literal (input-port-of self :buffering :full) nbytes)))
			(when (eof-object? n)
				  (error <smtp-error> "unexpected eof in literal."))
			(loop (+ nbytes n)))
		  (let ((str (u8vector->string literal)))
			((smtp-input-logger self) str)
			str)))))

(define-method recv-resp ((self <smtp>) . expected)
  (let loop ()
    (let ((m (#/^(\d+)(-| )(.*)/ (recv-line self))))
      (if
        (or (null? expected) 
            (string=? (car expected) (m 1)))
        (if (string=? " " (m 2)) #t
            (loop))
        (error <smtp-error> "Unexpected server reply." (m 1) (m 2) (m 3))))))

(define-method recv-resp->line ((self <smtp>) expected)
  (receive (index line match) (recv-resp self expected)
		   line))


(define (x->smtp-atom/list arg)
  (cond
   ((list? arg)
	(string-append "(" (string-join (map x->string arg)) ")"))
   (else
	(x->string arg))))

(define (x->smtp-list arg)
  (cond
   ((list? arg)
	(string-append "(" (string-join (map x->string arg)) ")"))
   ((not (string? arg))
	(string-append "(" (x->string arg) ")"))
   ((not (#/^\(.*\)$/ arg))
	(string-append "(" arg ")"))
   (else
	arg)))

(define (x->smtp-message-set arg)
  (cond
   ((list? arg)
	(string-join (map x->string arg) ","))
   (else
	(x->string arg))))

(define (date->smtp-date-time date)
  (format "\"~2d-~a-~4,'0d ~2,'0d:~2,'0d:~2,'0d ~a~2,'0d~2,'0d\""
		  (date-day date)
		  (list-ref '("Jan" "Feb" "Mar" "Apr" "May" "Jun"
					  "Jul" "Aug" "Sep" "Oct" "Nov" "Dec")
					 (- (date-month date) 1))
		  (date-year date)
		  (date-hour date) (date-minute date) (date-second date)
		  (if (>= (date-zone-offset date) 0) "+" "-")
		  (/ (abs (date-zone-offset date)) 3600)
		  (remainder (/ (abs (date-zone-offset date)) 60) 60)))

(define (x->smtp-date-time date)
  (cond
   ((date? date)
	(date->smtp-date-time date))
   ((not (string? date))
	(error <smtp-error> "unknown data type." date))
   ((#/^( |\d)\d\-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\-\d{4} \d{2}:\d{2}:\d{2} (\+|\-)\d{4}$/ date) ; without double quotation
	(string-append "\"" date "\""))
   ((#/^\"( |\d)\d\-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\-\d{4} \d{2}:\d{2}:\d{2} (\+|\-)\d{4}\"$/ date) ; with double quotation
	date)
   (else
	(error <smtp-error> "wrong date/time format." date))))


(provide "rfc/smtp")
