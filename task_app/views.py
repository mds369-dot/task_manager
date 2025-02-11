from django.contrib.auth import login, logout
from django.utils import timezone
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from .models import Category, Task
from django import forms
from django.urls import reverse
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.admin.views.decorators import staff_member_required


from django.core.exceptions import PermissionDenied
from django.db.models import Q




def is_admin(user):
    return user.is_superuser


admin_required = user_passes_test(lambda user: user.is_superuser)


def user_login(request):
    if request.method == 'POST':
        form = LoginForm(request, request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            if user.is_superuser:
                return redirect('category_list')
            else: 
                return redirect('user_tasks_list')
    else:
        form = LoginForm()
    return render(request, 'registration/login.html', {'form': form})


@login_required
def user_tasks_list(request):
    search_query = request.GET.get('search', '')  # Get search query from URL

    # Filter tasks based on search query
    if search_query:
        tasks = request.user.tasks.filter(
            Q(name__icontains=search_query) | 
            Q(description__icontains=search_query) |
            Q(assigned_to__username__icontains=search_query)
        )
    else:
        tasks = request.user.tasks.all()

    return render(request, 'user_task_list.html', {
        'tasks': tasks,
        'search_query': search_query  # Pass search query to template
    })

class RegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    def save(self, commit=True):
        user = super().save(commit=False)
        user.is_superuser = True 
        if commit:
            user.save()
        return user


class LoginForm(AuthenticationForm):
    class Meta:
        model = User
        fields = ['username', 'password']


def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            return redirect('login')
    else:
        form = RegistrationForm()
    return render(request, 'registration/register.html', {'form': form})

def LogoutPage(request):
    logout(request)
    return redirect("login")

def home(request):
    return render(request, 'home.html')


@login_required
@admin_required
def delete_task(request, task_id):
    if request.method == 'POST':
        task = Task.objects.get(id=task_id)
        task.delete()
    return redirect(reverse('category_list'))


@login_required
@admin_required
def create_task(request):
    if request.method == 'POST':
        # Retrieve data from the POST request
        name = request.POST.get('name')
        category_id = request.POST.get('category')
        start_date = request.POST.get('start_date')
        end_date = request.POST.get('end_date')
        priority = request.POST.get('priority')
        description = request.POST.get('description')
        location = request.POST.get('location')
        organizer = request.POST.get('organizer')
        assigned_to_id = request.POST.get('assigned_to')
        category = Category.objects.get(pk=category_id)
        task = Task.objects.create(
            name=name,
            category=category,
            start_date=start_date,
            end_date=end_date,
            priority=priority,
            description=description,
            location=location,
            organizer=organizer,
            assigned_to_id=int(assigned_to_id)
        )

        return redirect('category_list')
    else:
        categories = Category.objects.all()
        users = User.objects.all()
        return render(request, 'create_task.html', {'categories': categories, 'users': users})


@login_required
@admin_required
def update_task(request, task_id):
    task = get_object_or_404(Task, id=task_id)
    users = User.objects.all()  

    if request.method == 'POST':
        task.name = request.POST.get('name')
        task.start_date = request.POST.get('start_date')
        task.end_date = request.POST.get('end_date')
        task.priority = request.POST.get('priority')
        task.description = request.POST.get('description')
        task.location = request.POST.get('location')
        task.organizer = request.POST.get('organizer')
        assigned_to_id = request.POST.get('assigned_to')
        if assigned_to_id:
            task.assigned_to_id = assigned_to_id
        else:
            pass

        task.save()
        return redirect('category_list') 
    else:
        context = {
            'task': task,
            'users': users,
        }
        return render(request, 'update_task.html', context)

@login_required
@admin_required
def category_list(request):
    categories = Category.objects.all()
    return render(request, 'category_list.html', {'categories': categories})


@login_required
@admin_required
def create_category(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        Category.objects.create(name=name)
        return redirect('category_list')
    return render(request, 'create_category.html')


@login_required
@admin_required
def delete_category(request, category_id):
    category = Category.objects.get(pk=category_id)
    if category.task_set.exists():
        messages.error(
            request, "You cannot delete this category as it contains tasks.")
    else:
        category.delete()
        messages.success(request, "Category deleted successfully.")
    return redirect('category_list')


@login_required
@admin_required
def category_tasks(request, category_id):
    category = get_object_or_404(Category, pk=category_id)
    tasks = category.task_set.all()
    
    return render(request, 'category_tasks.html', {'category': category, 'tasks': tasks})


@login_required
@admin_required
def task_chart(request):
    categories = Category.objects.all()
    pending_counts = {}
    for category in categories:
        pending_counts[category.name] = Task.objects.filter(
            category=category,
            start_date__gt=timezone.now()
        ).count()
    return render(request, 'task_chart.html', {'pending_counts': pending_counts})

@login_required
@admin_required
def task_details(request, task_id):
    task = get_object_or_404(Task, id=task_id)
    return render(request, 'task_details.html', {'task': task})