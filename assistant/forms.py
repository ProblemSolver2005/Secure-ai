from django import forms
from .models import Incident

class IncidentForm(forms.ModelForm):
    class Meta:
        model = Incident
        fields = ['title', 'description', 'severity', 'source_ip', 'notes']
        widgets = {
            'title': forms.TextInput(attrs={'placeholder': 'e.g. Multiple failed SSH logins'}),
            'description': forms.Textarea(attrs={'rows': 4, 'placeholder': 'What happened? Include relevant evidence, not passwords or secrets.'}),
            'notes': forms.Textarea(attrs={'rows': 3, 'placeholder': 'Investigation notes (optional)'}),
        }

class AIQuestionForm(forms.Form):
    question = forms.CharField(max_length=4000, widget=forms.Textarea(attrs={
        'rows': 5, 'placeholder': 'Describe an error or paste a short, sanitized log excerpt…'
    }))
