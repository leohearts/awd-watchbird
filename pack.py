import re


RESOURCE_DIR = "resources/"
SOURCE_FILE = "watchbird-source.php"
OUTPUT_FILE = "watchbird.php"

if __name__ == "__main__":
    fp = open(SOURCE_FILE, 'r')
    source = fp.read()
    fp.close()
    for matchName in re.findall("{{@res-file:.*?}}", source):
        fileName = matchName.split("{{@res-file:", 1)[1].strip("}}")
        fp = open(RESOURCE_DIR + fileName, 'r')
        replaceC = fp.read()
        replaceC = replaceC.replace("\\", "\\\\")
        replaceC = replaceC.replace("$", "\\$")
        fp.close()
        source = source.replace(matchName, replaceC, 1)
    open(OUTPUT_FILE, 'w').write(source)
