from util.logging import logger

class PackageResult:
    def __init__(self, name, path, dataLibResults, sccmServer):
        self.name = name
        self.path = path
        self.dataLibResults = dataLibResults
        self.sccmServer = sccmServer

    def to_dict(self):
        return {
            "sccmServer": self.sccmServer,
            "pkgLibName": self.name,
            "pkgLibPath": self.path,
            "dataLibResults": [
                dataLibResult.to_dict() for dataLibResult in self.dataLibResults
            ],
        }

class DataLibResult:
    def __init__(self, name, path, results):
        self.name = name
        self.path = path
        self.results = results

    def to_dict(self):
        return {
            "name": self.name,
            "path": self.path,
            "results": [result.to_dict() for result in self.results],
        }

class FileLibResult:
    def __init__(self, name, path, results):
        self.name = name
        self.path = path
        self.results = results

    def to_dict(self):
        return {
            "name": self.name,
            "path": self.path,
            "results": [result.to_dict() for result in self.results],
        }

class Result:
    def __init__(self, filename, filePath, pattern, re_match, timemodified, filesize):
        self.filename = filename
        self.filePath = filePath
        self.pattern = pattern
        self.re_match = re_match
        self.timemodified = timemodified
        self.filesize = filesize
        try:
            if hasattr(re_match, "group"):
                self.matched_content = re_match.group(0)
            else:
                self.matched_content = ""
        except Exception:
            logger.error("Error in Result", exc_info=True)
        self.matched_content_expanded = ""
        if len(self.matched_content) > 400:
            self.matched_content = self.matched_content[:400]

    def to_dict(self):
        return {
            "filename": self.filename,
            "filePath": self.filePath,
            "pattern": self.pattern,
            "matched_content": self.matched_content,
            "matched_content_expanded": self.matched_content_expanded,
            "timemodified": self.timemodified,
            "filesize": self.filesize,
        }

    def get_expanded_result(self, content, lines_before, lines_after):
        """
        retrieves lines/characters before and after a match to get more context when looking at the matched content
        result = single Result
        content = content of file
        lines_before = number of lines to show before the match
        lines_after = number of lines to show after the match
        """
        try:
            lines = content.split("\n")
            match_start_line = content[:self.re_match.start()].count("\n")

            start_line = max(match_start_line - lines_before, 0)
            end_line = min(match_start_line + lines_after + 1, len(lines))

            out = ""
            for i in range(start_line, end_line):
                out += lines[i]+"\n"
                # if debugLvl == 3:
                #    print(lines[i].replace("\t",""))
            if len(out) > 400:
                logger.debug(
                    "Shortened expanded result because there seem to be no line breaks."
                )
                expanded_content = (
                    lines[
                        match_start_line
                    ]
                )
                while "  " in expanded_content:
                    expanded_content = expanded_content.replace("  ", "")
                if len(expanded_content) > 400:
                    return expanded_content[:400]
                return expanded_content
            if out == "":
                return ""
            return out
        except Exception as e:
            logger.error(f"Exception get_expanded_result: {e}", exc_info=True)
            return self.matched_content
