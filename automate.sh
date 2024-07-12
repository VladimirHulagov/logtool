pip list --not-required --format=freeze > requirements.txt
autopep8 -i -r logtool 
rm