/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-inferrable-types */
import { Component, EventEmitter, OnInit, Output, ViewEncapsulation } from '@angular/core';
import { Post } from 'src/app/common/post';
import { PostService } from 'src/app/service/post/post.service';
import { ToastrService } from 'ngx-toastr';
import { faPenToSquare, faTrash } from '@fortawesome/free-solid-svg-icons';

@Component({
  selector: 'app-manage-posts',
  templateUrl: './manage-posts.component.html',
  styleUrls: ['./manage-posts.component.css'],
})
export class ManagePostsComponent implements OnInit {

  postsList: Post[] = [];
  selectedPost: Post;
  storage: Storage = sessionStorage;
  openPost: boolean = false;

  // For searchbar in manage posts page:
  private _searchTerm: string = '';
  filteredPostsList: Post[] = [];

  // For pagination:
  page: number = 1;
  postsPerPage: number = 10;

  // Fontsawesome icons for update and delete buttons:
  faPenToSquare = faPenToSquare;
  faTrash = faTrash;

  @Output() cancel: EventEmitter<void> = new EventEmitter<void>();

  constructor(
    private postService: PostService,
    private toastr: ToastrService
  ) { }

  ngOnInit(): void {
    this.handleGetAllPosts();
  }

  handleGetAllPosts() {
    this.postService.getAllPosts().subscribe({
      next: (data: any) => {
        this.postsList = data;
        this.filterPosts();
      }
    });
  }

  updatePost(post: Post) {
    this.selectedPost = post;
    this.openPost = true;
  }

  deletePost(post: Post) {
    this.postService.deletePost(post.id).subscribe({
      next:(response: any) => {
        this.handleDeletePost(post);
        console.log(response)
        console.log(post)

        // Get updated list of posts:
        this.handleGetAllPosts();
      }
    })
  }

  handleDeletePost(post: Post) {
    const index = this.postsList.indexOf(post);
    if (index > -1) {
      this.postsList.splice(index, 1);
      this.toastr.success('Post deleted successfully!')
    }
  }
  
  closePostModal() {
    this.openPost = false;
    this.cancel.emit();
  }

  // For searchbar in manage posts page:
  filterPosts() {
    this.filteredPostsList = this.postsList.filter((post: Post) => {
      // Add filters for id / username / title / content:
      return post.id.toString().includes(this.searchTerm) ||
      (post.user.firstName ? post.user.firstName.toLowerCase().includes(this.searchTerm.toLowerCase()) : false) ||
      (post.user.lastName ? post.user.lastName.toLowerCase().includes(this.searchTerm.toLowerCase()) : false) ||
      (post.title ? post.title.toLowerCase().includes(this.searchTerm.toLowerCase()) : false) ||
      (post.caption ? post.caption.toLowerCase().includes(this.searchTerm.toLowerCase()) : false)
    })
  }

  get searchTerm(): string {
    return this._searchTerm;
  }

  set searchTerm(value: string) {
    this._searchTerm = value;
    this.filterPosts();
  }

  postUpdated(isUpdated: boolean) {
    if (isUpdated) {
      this.handleGetAllPosts();
    }
  }

  }
