import os
import re

html_file = r'c:\Users\ifilm\Downloads\Document\security-middleware\web\static\index.html'
with open(html_file, 'r', encoding='utf-8') as f:
    orig = f.read()

style_match = re.search(r'<style>\s*(.*?)\s*</style>', orig, flags=re.DOTALL)
script_match = re.search(r'<script>\s*(.*?)\s*</script>', orig, flags=re.DOTALL)

if style_match and script_match:
    css = style_match.group(1)
    js = script_match.group(1)
    
    css_dir = r'c:\Users\ifilm\Downloads\Document\security-middleware\web\static\css'
    os.makedirs(css_dir, exist_ok=True)
    with open(os.path.join(css_dir, 'styles.css'), 'w', encoding='utf-8') as f:
        f.write(css)
        
    js_dir = r'c:\Users\ifilm\Downloads\Document\security-middleware\web\static\js'
    os.makedirs(js_dir, exist_ok=True)
    with open(os.path.join(js_dir, 'app.js'), 'w', encoding='utf-8') as f:
        f.write(js)
        
    new_html = re.sub(r'<style>.*?</style>', '<link rel="stylesheet" href="/static/css/styles.css">', orig, flags=re.DOTALL)
    new_html = re.sub(r'<script>.*?</script>', '<script src="/static/js/app.js"></script>', new_html, flags=re.DOTALL)
    
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(new_html)
    print('Separated files successfully.')
else:
    print('Could not find style or script tags')
