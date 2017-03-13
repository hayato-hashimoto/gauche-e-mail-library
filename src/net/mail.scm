;; net/mail.scm
;; mail sending client library
;;

;; done: attachments
;; todo: non-ascii subject

(define-module net.mail
  (use gauche.charconv)
  (use rfc.smtp)
  (use rfc.base64)

  (export   smtp-start
            mail-to
            simple-message
            mime-multipart-message
            mime-attach-file
            add-field
            add-fields))

(select-module net.mail)

(define (smtp-start host port f)
  (define smtp (make <smtp>))
  (guard (e
    ((<smtp-error> e) (begin 
          (smtp-shutdown smtp)
          (raise e))))
   (begin (smtp-connect smtp host port)
          (f smtp)
          (smtp-disconnect smtp) #t)))

(define (mail-to to account message) 
  (smtp-start (value 'host account) (value 'port account) (lambda (smtp)
    (if (value 'auth account) 
        (smtp-authenticate smtp (value 'user account) 
           (value 'pass account) (value 'auth-type account)))
    (smtp.mail.from smtp (x->address (value 'from account)))
    (for-each (lambda (t) (smtp.rcpt.to smtp t)) (x->address-list to)) 
    (smtp.data smtp 
      (add-fields `(("From" ,(value 'from account))
                    ("To" ,to)) message)))))

(define (value key assoc-list)
   (cadr (assq key assoc-list)))

(define (store! key value assoc-list)
   (set-car! (cdr (assq key assoc-list)) value))

(define (add-field field value message)
  (string-append field ":" value "\r\n" message))

(define (add-fields pair-list message) 
  (fold (lambda (pair message) (add-field (car pair) (cadr pair) message)) message pair-list))

(define (with-fields pair-list message)
  (add-fields pair-list (string-append "\r\n" message)))

(define (mime-part message boundary)
  (string-append "\r\n--" boundary "\r\n" message))
(define (mime-part-end boundary)
  (string-append "\r\n--" boundary "--"))

(define (mime-attach-file file) 
   (with-fields `(("Content-Type" ,"text/plain")
                  ("Content-Transfer-Encoding" "base64")
                  ("Content-Disposition" ,(format "attachment; filename=\"~a\"" file)))
                           (with-output-to-string (lambda () (with-input-from-file file (lambda () (base64-encode)))))))

(define (simple-message subject text . encoding) 
  (define subject-port (open-output-string))
  (define text-port (open-output-string))
  (if (null? encoding) (set! encoding '("ISO-2022-JP")))
  (copy-port
   (open-input-conversion-port
    (open-input-string subject)
    "*JP" :to-code (car encoding))
   subject-port)
  (copy-port
   (open-input-conversion-port
    (open-input-string text)
    "*JP" :to-code (car encoding))
   text-port)
  (with-fields 
   `(("Content-Type" "text/plain; charset=ISO-2022-JP")
     ("Subject" ,(get-output-string subject-port)))
   (get-output-string text-port)))

(define (mime-multipart-message subject parts) 
  (define boundary "_BOUNDARY_+FKuIwojIA.fw78Q-Op9A8_JkoFW8oQjVv.iK+")
  (fold 
   (lambda (part s) 
     (string-append s (mime-part part boundary)))
   (with-fields 
    `(("Content-Type" ,(format "multipart/mixed; boundary=~a" boundary))
      ("Subject" ,subject)) "")
    parts))

(define (x->address s) s)
(define (x->address-list s) `(,s))

;;(mail-to "foo@example.com" my-account (simple-message "Hello, World!" "Message goes here ..."))

(provide "net/mail")
