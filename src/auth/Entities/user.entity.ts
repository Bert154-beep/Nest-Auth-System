import { Entity, PrimaryGeneratedColumn, Column } from "typeorm";

@Entity()
export class User{
    @PrimaryGeneratedColumn()
    id: number

    @Column({unique: true, type: 'varchar'})
    email: string

    @Column({ type: 'varchar'})
    userName: string

    @Column({type: 'text', nullable: true})
    password: string

    @Column({nullable: true, type: 'varchar'})
    otp: string | null

    @Column({nullable: true, type: 'timestamp'})
    otpExpires: Date | null
}