import { AbstractControl, FormControl, ValidationErrors } from '@angular/forms';
import { Observable, map } from 'rxjs';
import { UserService } from '../service/user/user.service';

export class FormValidators {
  // whitespace validation
  static notOnlyWhiteSpace(control: FormControl): ValidationErrors {
    // check if string only contains whitespace:
    if (control.value != null && control.value.trim().length === 0) {
      return { notOnlyWhiteSpace: true };
    } else {
      // valid - return empty object
      return {};
    }
  }

  static checkGender(control: FormControl): ValidationErrors {
    // Check if value is either "male" or "female"
    if (control.value !== 'male' && control.value !== 'female') {
      return { gender: true };
    } else {
      // valid - return empty object
      return {};
    }
  }

  static checkRole(control: FormControl): ValidationErrors {
    // Check if value is either "user" or "admin"
    if (control.value !== 'user' && control.value !== 'admin') {
      return { role: true };
    } else {
      // valid - return empty object
      return {};
    }
  }

  // Mock Aysnc to test (Observable)
  // static emailExistCheckWithDatabase = function (
  //   control: AbstractControl
  // ): Promise<ValidationErrors | null> | Observable<ValidationErrors | null>{
  //    return new Observable((observer) => {
  //     setTimeout(() => {
  //       if (control.value === 'kohhxxx') {
  //         observer.next({ userNameCheckDb: true });
  //       } else {
  //         observer.next(null);
  //       }
  //       observer.complete();
  //     }, 2000);
  //    })
  //   }
  // ;

  // Mock Aysnc to test (Observable)
  static emailExistCheckWithDatabase = function (userService: UserService) {
    return function (
      control: AbstractControl
    ): Promise<ValidationErrors | null> | Observable<ValidationErrors | null> {
      return userService.existsByEmail(control.value)
        .pipe(
          map((result: boolean) =>{
           return  result ? { usernameAlreadyExists: true } : null;
          }
          )
        );
    };
  };
}
