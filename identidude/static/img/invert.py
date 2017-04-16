import os
from lxml import etree

tint = "#ffffff"
suffix = "-inverted.svg"

for filename in os.listdir("."):
    basename, extension = os.path.splitext(filename)
    if extension.lower() != ".svg":
        continue
    if filename.endswith(suffix):
        continue

    print "Inverting:", filename
    inverted = basename + suffix

    parser = etree.XMLParser(remove_blank_text=True, remove_comments=True)
    tree = etree.parse(filename, parser)
    root = tree.getroot()

    for j in tree.findall("//"):
        j.attrib["fill"] = tint


    # Inject CSS stylesheets is not neccessary if SVG is inlined
    with open(inverted, "wb") as sh:
        try:
            tree.write(sh, inclusive_ns_prefixes=False)
        except TypeError: # Support wheezy's older python-lxml
            tree.write(sh)

