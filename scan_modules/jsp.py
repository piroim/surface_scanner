"""JSP, Java Servlet, and JVM web framework fingerprints."""

from __future__ import annotations

from .base import Signature, TechnologyModule, regex


class JspModule(TechnologyModule):
    key = "jsp"
    label = "JSP/Java"
    aliases = ("jsp", "java", "servlet")
    route_suffixes = (".jsp", ".jspx", ".do", ".action")
    signatures = (
        Signature("header", regex(r"Apache-Coyote|Tomcat"), "서블릿 컨테이너", "Apache Tomcat", "high", "server"),
        Signature("header", regex(r"Jetty"), "서블릿 컨테이너", "Eclipse Jetty", "high", "server"),
        Signature("header", regex(r"WildFly|JBoss"), "애플리케이션 서버", "WildFly/JBoss", "high", "server"),
        Signature("header", regex(r"WebLogic"), "애플리케이션 서버", "Oracle WebLogic", "high", "server"),
        Signature("header", regex(r"WebSphere"), "애플리케이션 서버", "IBM WebSphere", "high", "server"),
        Signature("header", regex(r"Undertow"), "서블릿 컨테이너", "Undertow", "high", "server"),
        Signature("header", regex(r"Servlet|JSP"), "런타임", "Java Servlet/JSP", "high", "x-powered-by"),
        Signature("header", regex(r"JSESSIONID"), "세션", "JSESSIONID", "high", "set-cookie"),
        Signature("body", regex(r"Whitelabel Error Page|org\.springframework|spring-webmvc"), "프레임워크", "Spring", "high"),
        Signature("body", regex(r"struts\.action|org\.apache\.struts"), "프레임워크", "Apache Struts", "high"),
        Signature("body", regex(r"javax\.servlet|jakarta\.servlet"), "런타임", "Java Servlet", "high"),
    )


MODULE = JspModule()
