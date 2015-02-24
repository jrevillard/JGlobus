package org.globus.common;

public class ChainedIOException extends java.io.IOException {
	private static final long serialVersionUID = 1L;
	/**
     * The possibly null root cause exception.
     * @serial
     */
    private Throwable exception;

    /**
     * Constructs a new instance of <tt>ChainedIOException</tt>.
     * The root exception and the detailed message are null.
     */
    public ChainedIOException () {
        super();
    }

    /**
     * Constructs a new instance of <tt>ChainedIOException</tt> with a
     * detailed message. The root exception is null.
     *
     * @param detail A possibly null string containing details of the
     *        exception.
     *
     * @see java.lang.Throwable#getMessage
     */
    public ChainedIOException (String detail) {
        super(detail);
    }

    /**
     * Constructs a new instance of <tt>ChainedIOException</tt> with a
     * detailed message and a root exception.
     *
     * @param detail A possibly null string containing details of the
     *        exception.
     * @param ex A possibly null root exception that caused this exception.
     *
     * @see java.lang.Throwable#getMessage
     * @see #getException
     */
    public ChainedIOException (String detail, Throwable ex) {
        super(detail, ex);
        exception = ex;
    }

    /**
     * Returns the root exception that caused this exception.
     * @return The possibly null root exception that caused this exception.
     */
    public Throwable getException() {
        return exception;
    }

    /**
     * Prints this exception's stack trace to <tt>System.err</tt>.
     * If this exception has a root exception; the stack trace of the
     * root exception is printed to <tt>System.err</tt> instead.
     */
    public void printStackTrace() {
        printStackTrace( System.err );
    }

    /**
     * Prints this exception's stack trace to a print stream.
     * If this exception has a root exception; the stack trace of the
     * root exception is printed to the print stream instead.
     * @param ps The non-null print stream to which to print.
     */
    public void printStackTrace(java.io.PrintStream ps) {
        if ( exception != null ) {
            String superString = getLocalMessage();
            synchronized ( ps ) {
                ps.print(superString);
                ps.print((superString.endsWith(".") ?
                          " Caused by " : ". Caused by "));
                exception.printStackTrace( ps );
            }
        } else {
            super.printStackTrace( ps );
        }
    }

    /**
     * Prints this exception's stack trace to a print writer.
     * If this exception has a root exception; the stack trace of the
     * root exception is printed to the print writer instead.
     * @param pw The non-null print writer to which to print.
     */
    public void printStackTrace(java.io.PrintWriter pw) {
        if ( exception != null ) {
            String superString = getLocalMessage();
            synchronized (pw) {
                pw.print(superString);
                pw.print((superString.endsWith(".") ?
                          " Caused by " : ". Caused by "));
                exception.printStackTrace( pw );
            }
        } else {
            super.printStackTrace( pw );
        }
    }

    public String getMessage() {
        String answer = super.getMessage();
        if (exception != null && exception != this) {
            String msg = exception.getMessage();
            if (msg == null) {
                msg = exception.getClass().getName();
            }
            answer += " [Caused by: " + msg + "]";
        }
        return answer;
    }

    private String getLocalMessage() {
        String message = super.getMessage();
        return (message == null) ? getClass().getName() : message;
    }

}
