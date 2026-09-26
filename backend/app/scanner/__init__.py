from . import headers, cookies, clickjacking, ssl_check, tech_detect, dir_enum, csrf, xss, sqli

MODULE_REGISTRY = {
    "headers": headers.run,
    "cookies": cookies.run,
    "clickjacking": clickjacking.run,
    "ssl_tls": ssl_check.run,
    "tech_detect": tech_detect.run,
    "dir_enum": dir_enum.run,
    "csrf": csrf.run,
    "xss": xss.run,
    "sqli": sqli.run,
}
