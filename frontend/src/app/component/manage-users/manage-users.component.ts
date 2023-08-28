/* eslint-disable @typescript-eslint/no-inferrable-types */
import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { faPenToSquare, faTrash } from '@fortawesome/free-solid-svg-icons';
import { ToastrService } from 'ngx-toastr';
import { User } from 'src/app/common/user';
import { UserService } from 'src/app/service/user/user.service';

@Component({
  selector: 'app-manage-users',
  templateUrl: './manage-users.component.html',
  styleUrls: ['./manage-users.component.css'],
})
export class ManageUsersComponent implements OnInit {
  usersList: User[] = [];
  selectedUser: User;
  storage: Storage = sessionStorage;
  openUser: boolean = false;
  defaultImage =
    'https://w7.pngwing.com/pngs/754/2/png-transparent-samsung-galaxy-a8-a8-user-login-telephone-avatar-pawn-blue-angle-sphere-thumbnail.png';

  // For searchbar in manage users page:
  private _searchTerm: string = '';
  filteredUsersList: User[] = [];

  // For pagination:
  page: number = 1;
  usersPerPage: number = 10;

  // Fontsawesome icons for update and delete buttons:
  faPenToSquare = faPenToSquare;
  faTrash = faTrash;

  // Finding user role from session storage:
  userRole = sessionStorage.getItem('role')?.split(',');

  constructor(
    private userService: UserService,
    private toastr: ToastrService,
    private router: Router
  ) {}

  ngOnInit(): void {
    this.handleGetAllUsers();
  }

  handleGetAllUsers() {
    this.userService.getAllUsers().subscribe((data: any) => {
      console.log(data);
      this.usersList = data;
      this.filteredUsersList = data;
    });
  }

  updateUser(user: User) {
    console.log(user);
    this.selectedUser = user;
    this.openUser = true;
  }

  updatedUser(isUpdated: boolean) {
    if (isUpdated) {
      console.log("Change liao")
      this.handleGetAllUsers();
    }
  }

  deleteUser(user: User) {
    this.userService.deleteUser(user.id).subscribe({
      next: (response: any) => {
        this.handleDeleteUser(user);
        console.log(response);
        console.log(user);

        // Get updated list of users:
        this.handleGetAllUsers();
      },
    });
  }

  handleDeleteUser(user: User) {
    const index = this.usersList.indexOf(user);
    if (index > -1) {
      this.usersList.splice(index, 1);
      this.toastr.success('User deleted successfully!');
    }
  }

  closeUserModal() {
    this.openUser = false;
  }

  // For searchbar in manage users page:
  filterUsers() {
    this.filteredUsersList = this.usersList.filter((user: User) => {
      // Add filers for id / name / email:
      return (
        user.id.toString().includes(this.searchTerm) ||
        (user.firstName
          ? user.firstName.toLowerCase().includes(this.searchTerm.toLowerCase())
          : false) ||
        (user.lastName
          ? user.lastName.toLowerCase().includes(this.searchTerm.toLowerCase())
          : false) ||
        (user.email
          ? user.email.toLowerCase().includes(this.searchTerm.toLowerCase())
          : false)
      );
    });
  }

  get searchTerm(): string {
    return this._searchTerm;
  }

  set searchTerm(value: string) {
    this._searchTerm = value;
    this.filterUsers();
  }

  goToUserProfile(userId: number) {
    this.router.navigate([`/users/${userId}/posts`]);
  }

}
