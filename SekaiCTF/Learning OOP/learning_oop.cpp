

#include<iostream>
#include<cstring>
#include<string>

#define MAX_PET_COUNT 10

enum Status {
    FULL = 1,
    WELLRESTED = 2,
};

class Animal {
    public:
        Animal() {
            memset(this->name, 0x41, sizeof(this->name));
            this->age = 0;
            this->fullness = 10;
            this->status = Status::FULL | Status::WELLRESTED;
        }
        virtual void eat() {
            std::cout << "NOM" << std::endl;
            this->fullness = 20;
            this->status |= Status::FULL;
        }
        virtual void sleep() {
            std::cout << "ZZZ" << std::endl;
            this->status |= Status::WELLRESTED;
        }
        virtual void play() {
            std::cout << "Played with " << this->name << std::endl;
            this->status = 0;
        }
        virtual constexpr size_t get_max_age() = 0; // pure virtual function
        int age_up() {
            return ++this->age;
        }
        int fullness_down() {
            return --this->fullness;
        }
        void set_name() {
            std::cout << "Enter name: " << std::endl;
            std::cin >> this->name;
        }
        char* get_name() {
            return this->name;
        }
        int get_status() {
            return this->status;
        }
        void die() {
            std::cout << this->name << " died :(" << std::endl;
            return;
        }
    protected:
        char name[0x100];
        int age;
        int fullness;
        int status;
};

class Dog : public Animal {
    public:
        constexpr size_t get_max_age() override { return 25; }
        void play() {
            std::cout << this->name << " says: woof woof!" << std::endl;
            this->status = 0;
        }
};

class Cat : public Animal {
        constexpr size_t get_max_age() override { return 20; }
        void play() {
            std::cout << this->name << " says: meow." << std::endl;
            this->status = 0;
        }
        void sleep() {
            std::cout << this->name << " slept for 20 hours." << std::endl;
            this->status |= Status::WELLRESTED;
        }
};

class Parrot : public Animal {
        constexpr size_t get_max_age() override { return 14; }
        void play() {
            std::cout << this->name << " says: give me 10000$ for the flag!" << std::endl;
            this->status = 0;
        }
        void eat() {
            std::cout << "Polly want a cracker!" << std::endl;
            this->status |= Status::FULL;
        }
};

class Horse : public Animal {
        constexpr size_t get_max_age() override { return 40; }
        void play() {
            std::cout << "UMAZING!!!" << std::endl;
            this->status = 0;
        }
        void eat() {
            std::cout << "UMAI!!!!" << std::endl;
            this->status |= Status::FULL;
        }
        void sleep() {
            std::cout << "UMAAAANTUK!!!!" << std::endl;
            this->status |= Status::WELLRESTED;
        }
};

int num_pets;
Animal* pets[MAX_PET_COUNT]; // why would anyone need more than 10 pets?

void init() {
    memset(pets, 0, sizeof(pets));
    return;
}

void menu() {
    std::cout << "1. Adopt new pet" << std::endl;
    std::cout << "2. Play with pet" << std::endl;
    std::cout << "3. Feed pet" << std::endl;
    std::cout << "4. Rest pet" << std::endl;
    std::cout << "5. Exit" << std::endl;
    std::cout << "> ";
}

void update() {

    for(size_t i = 0; i < MAX_PET_COUNT; i++) {
        Animal* pet = pets[i];
        if(pet != nullptr) {
            if(pet->fullness_down() == 0 || pet->age_up() > pet->get_max_age()) {
                pet->die();
                delete pet;
                pets[i] = nullptr;
                num_pets--;
            }
        }
    }
    return;
}

void new_pet() {

    int pet_choice = 0;
    if(num_pets >= MAX_PET_COUNT) {
        std::cout << "You have too many pets already" << std::endl;
        return;
    }
    std::cout << "Choose pet species (1=Dog, 2=Cat, 3=Parrot, 4=Horse): ";
    std::cin >> pet_choice;
    if(!std::cin.good()) {
        std::cout << "I/O Error" << std::endl;
        exit(EXIT_FAILURE);
    }
    Animal* new_pet = nullptr;
    switch(pet_choice) {
        case 1:
            new_pet = new Dog();
            break;
        case 2:
            new_pet = new Cat();
            break;
        case 3:
            new_pet = new Parrot();
            break;
        case 4:
            new_pet = new Horse();
            break;
        default:
            std::cout << "Invalid!" << std::endl;
            return;
    }

    new_pet->set_name();
    for(size_t i = 0; i < MAX_PET_COUNT; i++) {
        if(pets[i] == nullptr) {
            pets[i] = new_pet;
            break;
        }
    }
    num_pets++;
    std::cout << "Adopted new pet: " << new_pet << std::endl; // TODO: fix
    return;
}

void print_pets() {
    int cnt = 0;
    for(size_t i = 0; i < MAX_PET_COUNT; i++) {
        if(pets[i] != nullptr) {
            std::cout << cnt++ << ". " << pets[i]->get_name() << std::endl;
        }
    }
    return;
}

void play_with_pet() {
    int pet_choice = 0;
    if(num_pets == 0) {
        std::cout << "You dont have any pets" << std::endl;
        return;
    }
    print_pets();
    std::cout << "Which pet? " << std::endl;
    std::cin >> pet_choice;
    if(pet_choice < 0 || pet_choice >= MAX_PET_COUNT || pets[pet_choice] == nullptr) {
        std::cout << "Invalid!" << std::endl;
        return;
    }
    if(pets[pet_choice]->get_status() & Status::WELLRESTED == 0) {
        std::cout << "Pet is too tired!" << std::endl;
        return;
    }
    pets[pet_choice]->play();
    return;
}

void feed_pet() {
    int pet_choice = 0;
    if(num_pets == 0) {
        std::cout << "You dont have any pets" << std::endl;
        return;
    }
    print_pets();
    std::cout << "Which pet? " << std::endl;
    std::cin >> pet_choice;
    if(pet_choice < 0 || pet_choice >= MAX_PET_COUNT || pets[pet_choice] == nullptr) {
        std::cout << "Invalid!" << std::endl;
        return;
    }
    pets[pet_choice]->eat();
    return;
}

void rest_pet() {
    int pet_choice = 0;
    if(num_pets == 0) {
        std::cout << "You dont have any pets" << std::endl;
        return;
    }
    print_pets();
    std::cout << "Which pet? " << std::endl;
    std::cin >> pet_choice;
    if(pet_choice < 0 || pet_choice >= MAX_PET_COUNT || pets[pet_choice] == nullptr) {
        std::cout << "Invalid!" << std::endl;
        return;
    }
    pets[pet_choice]->sleep();
    return;
}

int main(int argc, char *argv[]) {
    init();

    int choice = 0;
    while(1) {
        menu();
        std::cin >> choice;
        if(!std::cin.good()) {
            std::cout << "I/O Error" << std::endl;
            return EXIT_FAILURE;
        }
        switch(choice) {
            case 1:
                new_pet();
                break;
            case 2:
                play_with_pet();
                break;
            case 3:
                feed_pet();
                break;
            case 4:
                rest_pet();
                break;
            case 5:
                if(num_pets != 0) {
                    std::cout << "No, you still have pets. You cant abandon them :(" << std::endl;
                    break;
                }
                std::cout << "Bye bye" << std::endl;
                return 0;
            default:
                std::cout << "You did nothing" << std::endl;
                break;
        }
        update();
    }
    return 0;
}
