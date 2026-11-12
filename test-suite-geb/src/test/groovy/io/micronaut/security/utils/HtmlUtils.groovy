package io.micronaut.security.utils

class HtmlUtils {
    static String securedPage() {
        StringBuilder sb = new StringBuilder()
        sb.append("<!DOCTYPE html>")
        sb.append("<html>")
        sb.append("<head>")
        sb.append("<title>Secured Page</title>")
        sb.append("</head>")
        sb.append("<body>")
        sb.append("</body>")
        sb.append("</html>")
        return sb.toString()
    }

    static String homePage(boolean loggedIn, String username) {
        StringBuilder sb = new StringBuilder()
        sb.append("<!DOCTYPE html>")
        sb.append("<html>")
        sb.append("<head>")
        sb.append("<title>Home</title>")
        sb.append("</head>")
        sb.append("<body>")
        if( loggedIn ) {
            sb.append("<h1>username: <span> "+username+"</span></h1>")
        } else {
            sb.append("<h1>You are not logged in</h1>")
        }
        if( loggedIn ) {
            sb.append("<form action=\"logout\" method=\"POST\">")
            sb.append("<input type=\"submit\" value=\"Logout\" />")
            sb.append("</form>")
        } else {
            sb.append("<p><a href=\"/login/auth\">Login</a></p>")
        }
        sb.append("</body>")
        sb.append("</html>")
        return sb.toString()
    }

    static String login(boolean errors) {
        StringBuilder sb = new StringBuilder()
        sb.append("<!DOCTYPE html>")
        sb.append("<html>")
        sb.append("<head>")
        if( errors ) {
            sb.append("<title>Login Failed</title>")
        } else {
            sb.append("<title>Login</title>")
        }
        sb.append("</head>")
        sb.append("<body>")
        sb.append("<form action=\"/login\" method=\"POST\">")
        sb.append("<ol>")
        sb.append("<li>")
        sb.append("<label for=\"username\">Username</label>")
        sb.append("<input type=\"text\" name=\"username\" id=\"username\"/>")
        sb.append("</li>")
        sb.append("<li>")
        sb.append("<label for=\"password\">Password</label>")
        sb.append("<input type=\"text\" name=\"password\" id=\"password\"/>")
        sb.append("</li>")
        sb.append("<li>")
        sb.append("<input type=\"submit\" value=\"Login\"/>")
        sb.append("</li>")
        if( errors ) {
            sb.append("<li id=\"errors\">")
            sb.append("<span style=\"color:red\">Login Failed</span>")
            sb.append("</li>")
        }
        sb.append("</ol>")
        sb.append("</form>")
        sb.append("</body>")
        sb.append("</html>")
        return sb.toString()
    }
}
