"""
DataFilter is a single-file library written on Python used to check data for presence of sql injections

For full documentation, see the README.MD file in the project's GitHub repository
Link to repository: https://github.com/Mavment/DataFilter
"""

import re

#Groups of symbols for quick allowed symbols array assembling
symbolsDict = {
    "ascii_lowercase": "abcdefghijklmnopqrstuvwxyz",
    "ascii_uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "numbers": "1234567890",
    "special": "!@#$%^&*()_-+=:;<>,.?/*",
}

#Often used sql keywords
_SQL_KEYWORDS = [
    "select", "insert", "update", "delete", "replace", "truncate",
    "create", "alter", "drop", "rename", "grant", "revoke", "use",
    "describe", "desc", "show", "explain",

    "from", "where", "having", "group by", "order by", "limit", "offset",
    "top", "fetch", "into", "values", "returning", "union", "union all",
    "intersect", "except", "distinct", "case", "when", "then", "else", "end",

    "and", "or", "not", "xor", "like", "ilike", "rlike", "regexp", "similar to",
    "in", "exists", "all", "any", "between", "is", "null", "is null",
    "is not null", "=", "==", "!=", "<>", ">", "<", ">=", "<=",

    "--", "#", "/*", "*/", ";", "-- ", "# ",

    "cast", "convert", "concat", "concat_ws", "group_concat", "string_agg",
    "substr", "substring", "left", "right", "mid", "instr", "locate",
    "length", "char_length", "len", "upper", "lower", "trim", "ltrim", "rtrim",
    "replace", "replace(", "ascii", "char", "chr", "hex", "unhex",

    "+", "-", "*", "/", "%", "mod", "power", "floor", "ceil",

    "exec", "execute", "sp_executesql", "execute immediate", "prepare",
    "deallocate", "execute immediate", "declare", "set", "select into",
    "openrowset", "opendatasource", "openquery", "bulk insert", "bcp",

    "version", "@@version", "version()", "user()", "current_user", "session_user",
    "system_user", "@@hostname", "@@datadir", "@@identity", "@@rowcount",
    "database()", "schema_name", "schema()", "database", "schema",

    "sleep", "benchmark", "load_file", "into outfile", "into dumpfile",
    "information_schema", "performance_schema", "mysql.user", "found_rows",
    "updatexml", "extractvalue", "group_concat", "benchmark(", "sleep(",

    "pg_sleep", "pg_read_file", "pg_ls_dir", "pg_read_binary_file",
    "pg_shadow", "pg_roles", "pg_database", "pg_user", "pg_catalog", "current_database",

    "xp_cmdshell", "sp_msforeachdb", "sp_msforeachtable", "xp_dirtree",
    "xp_availablemedia", "xp_regread", "xp_regwrite", "sp_oacreate",
    "sp_oamethod", "sp_oaputfile", "sp_configure", "master..", "sysobjects",
    "sysdatabases", "information_schema.tables", "sys.tables", "sys.schemas",
    "bulkadmin", "dbcc", "OPENROWSET", "OPENDATASOURCE", "xp_subdirs",

    "dbms_lock.sleep", "dbms_pipe.receive_message", "dbms_output", "utl_http.request",
    "utl_file", "utl_file.fopen", "all_users", "dba_users", "user_users",
    "v$version", "v$instance", "xmltype", "extractvalue", "updatexml",
    "to_char", "to_date", "rownum", "connect by", "sys.dba_users",

    "sqlite_master", "pragma", "attach", "detach", "load_extension",

    "into outfile", "into dumpfile", "load_file(", "xp_cmdshell", "shell",
    "cmd.exe", "powershell", "wget", "curl", "ftp", "into incremental", "outfile",

    "xmltype", "extractvalue", "updatexml", "xpath", "json_extract", "jsonb_extract_path",
    "jsonb_each", "json_each", "jsonb_each_text",

    "information_schema.columns", "information_schema.tables",
    "information_schema.routines", "information_schema.schemata",
    "pg_catalog.pg_tables", "pg_catalog.pg_roles", "all_tables", "dba_tables",

    "inet_server_addr", "inet_server_port", "version()", "session_user()",
    "current_user()", "user()", "database()", "schema()", "schema_name()",

    "' or '1'='1", "\" or \"1\"=\"1", "' or 1=1 --", "\" or 1=1 --",
    "or1=1", "or'1'='1", "or\"1\"=\"1", "or 1=1", "or '1'='1'",
    "' or 'x'='x", "\" or \"x\"=\"x",

    "count(", "sum(", "avg(", "min(", "max(",

    "sp_tables", "sp_columns", "sp_help", "sp_helptext", "sp_who", "sp_who2",
    "sp_password", "sp_addsrvrolemember", "sp_addlinkedserver",

    "grant", "revoke", "create user", "alter user", "drop user", "create role",
    "dba_", "all_", "role_", "privileges", "has_privilege",

    "concat(", "group_concat(", "string_agg(", "regexp_replace", "regexp_like",
    "instr(", "position(", "pg_sleep(", "sleep(", "benchmark(", "waitfor delay",
    "waitfor", "delay", "dbms_lock.sleep(", "utl_http.request(", "utl_inaddr.get_host_address",

    "having", "limit", "offset", "order", "by", "group", "procedure", "function",
    "trigger", "triggered", "cursor", "open", "fetch", "close", "loop", "if", "elsif",
    "elsif", "else", "end", "case", "while", "for", "begin", "declare", "exception",

    "||", "+", "concat", "concat_ws", "0x", "0x", "/*", "*/", "--", "#",

    "unionselect", "union all select", "union allselect", "unionselect", "union--", "union/*",
    "sleep(", "benchmark(", "benchmark(", "intooutfile", "intodumpfile", "intooutfile(",

    "xmlserialize", "xmlagg", "db2.", "teradata", "tdg", "sysibm", "qsys2", "syscat",
    "SYSDUMMY1", "sysobjects", "syscolumns", "syscomments", "sys.sql_modules",

    "passwd", "password", "pwd", "hash", "salt", "credit_card", "ssn", "social_security_number",

    "load_file(", "openrowset(", "xp_cmdshell(", "sp_oacreate(", "sp_oamethod(",

    "' or '1'='1", "' or 1=1", "\" or 1=1", "' or 'a'='a", "\" or \"a\"=\"a\"",
    "or'1'='1", "or\"1\"=\"1", "or1=1", "or 1=1 --", "1=1 --",

    "mysql.user", "pg_shadow", "pg_user", "dba_users", "all_users", "user_users",
    "information_schema", "performance_schema", "pg_catalog", "v$session", "v$instance",

    "extractvalue(", "updatexml(", "xmlquery(", "xmltable(",

    "hex(", "unhex(", "base64_decode(", "from_base64(", "to_base64(", "decode(",

    "msdb.dbo.backupset", "msdb.dbo.restorefile", "msdb", "master.dbo", "dba_tables", "all_tables",

    "xp_cmdshell", "xp_dirtree", "xp_regread", "xp_regwrite", "xp_subdirs", "openquery", "openrowset",

    "selecting", "selection", "selected", "dropbox", "updateable"
]

#Filtering patterns used in regex
_PATTERNS = {
    "sql_comment": re.compile(r"(--|#)(?!\S)", re.IGNORECASE),
    "sql_comment_multi": re.compile(r"/\*.*?\*/", re.IGNORECASE | re.DOTALL),
    "tautology_numeric": re.compile(r"(?:'|\")?\s*or\s+1\s*=\s*1\b", re.IGNORECASE),
    "tautology_string": re.compile(r"(?:'|\")\s*or\s+['\"][^'\"]+['\"]\s*=\s*['\"][^'\"]+['\"]", re.IGNORECASE),
    "union_select": re.compile(r"\bunion\b\s*(all\s*)?\bselect\b", re.IGNORECASE),
    "stacked_query": re.compile(r";\s*(select|insert|update|delete|drop|create|alter|exec|declare)\b", re.IGNORECASE),
    "time_based": re.compile(r"\b(sleep|pg_sleep|benchmark)\s*\(", re.IGNORECASE),
    "hex_or_char": re.compile(r"\b0x[0-9a-f]+\b|\bchar\s*\(|\bchr\s*\(", re.IGNORECASE),
    "always_true_like": re.compile(r"(?:(?:'|\")\s*=\s*(?:'|\"))|(?:'\s*or\s*'x'='x')", re.IGNORECASE),
    "sql_keyword_used": re.compile(r"\b(" + "|".join(map(re.escape, _SQL_KEYWORDS)) + r")\b", re.IGNORECASE),
    "logical_expression": re.compile(r"\b(or|and)\b\s+[^=<>]+\s*(=|>|<)", re.IGNORECASE)
}

#Filtering patterns used in regex (ignore spaces)
_PATTERNSDEEP = {
    "sql_comment": re.compile(r"--|#", re.IGNORECASE),
    "sql_comment_multi": re.compile(r"/\*.*?\*/", re.IGNORECASE | re.DOTALL),
    "tautology_numeric": re.compile(r"(?:'|\")?or1=1", re.IGNORECASE),
    "tautology_string": re.compile(r"(?:'|\")or['\"][^'\"]+['\"]=['\"][^'\"]+['\"]", re.IGNORECASE),
    "union_select": re.compile(r"union(all)?select", re.IGNORECASE),
    "stacked_query": re.compile(r";(select|insert|update|delete|drop|create|alter|exec|declare)", re.IGNORECASE),
    "time_based": re.compile(r"(sleep|pg_sleep|benchmark)\(", re.IGNORECASE),
    "hex_or_char": re.compile(r"0x[0-9a-f]+|char\(|chr\(", re.IGNORECASE),
    "always_true_like": re.compile(r"(?:'|\")=(?:'|\")|'or'x'='x'", re.IGNORECASE),
    "sql_keyword_used": re.compile("(" + "|".join(map(re.escape, _SQL_KEYWORDS)) + ")", re.IGNORECASE),
    "logical_expression": re.compile(r"(or|and)[^=<>]*(=|>|<)", re.IGNORECASE)
}

class DataFilterException(Exception):
    """DataFilterException internal library exception class
    """
    def __init__(self, text: str = "Unknown exception occured"):
        super().__init__(text)

class filterReport:
    """Report structure base, returned by filter functions

    Struction includes:
    data - initial data that was inputted in filter function (string)
    status - code phrase filter function returns:
             OK - no detections
             FOUND - suspicous data found
             DETECTED - sqli found or data is too suspicous (many detections)

    detections - array of names of possibly used sqli strategies:
                 if status is FOUND includes array of strings - short names of detected vulnerabilities usage in data
                 if status is OK - empty array

    issecure - defines if data is secure or dangerous:
               True if data is considered secure
               False if data may be dangerous
    """
    def __init__(self, data: str = b"", status: str = "None", detections: list[str] = None, issecure: bool = False) -> None:
        self.data: str = data
        self.status: str = status
        self.detections: list[str] = detections if detections != None else []
        self.issecure: bool = issecure
    
def strSQLICheck(data: str, allowedSymbols: str = "", deepSearch: bool = False) -> filterReport:
    """strSQLICheck checks data for usage of sqli vulnerability

    :param data: data to be checked
    :type data: str
    :param allowedSymbols: string of allowed in data symbols
        if there is a symbol which is not in allowedSymbols, function returns DETECTED status, defaults to ""
    :type allowedSymbols: str, optional
    :param deepSearch: if set to True, spaces in data are ignored
        Attention!!! may result in a lots of false positives, defaults to False
    :type deepSearch: bool, optional
    :raises DataFilterException: _description_
    :return: report, including results of check
    :rtype: filterReport
    """

    if type(data) != str:
        raise DataFilterException(f"INVALID_INPUT: strSQLICheck expected str, instead got {type(data)}")
    
    if allowedSymbols:
        tempdata = data
        for symbol in allowedSymbols:
            tempdata = tempdata.replace(symbol,"")
        if tempdata:
            return filterReport(data, status = "DETECTED", detections = ["banned_symbol_usage"], issecure = False)

    _checkedPatterns = (_PATTERNSDEEP if deepSearch else _PATTERNS)

    report = filterReport(data, status = "OK", issecure = True)

    if "'" in data or '"' in data:
        has_quote = True
        report.detections.append("qoutes_usage")
        report.status = "FOUND"
        report.issecure = False
    else:
        has_quote = False

    def match_add(name: str) -> None:
        if _checkedPatterns[name].search(data):
            report.detections.append(name)
            if has_quote:
                report.issecure = False
                report.status = "DETECTED"
            else:
                report.status = "FOUND"

    for pattern in _checkedPatterns:
        match_add(pattern)

    if len(report.detections) >= 2:
        report.issecure = False

    return report
